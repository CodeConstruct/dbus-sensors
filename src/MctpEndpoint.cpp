#include "MctpEndpoint.hpp"

#include "Utils.hpp"

#include <boost/system/detail/errc.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/message.hpp>
#include <sdbusplus/message/native_types.hpp>

#include <exception>
#include <memory>
#include <system_error>

static constexpr const char* mctpdBusName = "xyz.openbmc_project.MCTP";
static constexpr const char* mctpdControlPath = "/xyz/openbmc_project/mctp";
static constexpr const char* mctpdControlInterface =
    "au.com.CodeConstruct.MCTP";
static constexpr const char* mctpdEndpointControlInterface =
    "au.com.CodeConstruct.MCTP.Endpoint";

MctpdDevice::MctpdDevice(
    const std::shared_ptr<sdbusplus::asio::connection>& connection,
    const std::string& interface, const std::vector<uint8_t>& physaddr) :
    connection(connection), interface(interface), physaddr(physaddr)
{}

void MctpdDevice::onEndpointInterfacesRemoved(
    const std::weak_ptr<MctpdDevice>& weak, const std::string& objpath,
    sdbusplus::message_t& msg)
{
    auto path = msg.unpack<sdbusplus::message::object_path>();
    if (path.str != objpath)
    {
        return;
    }

    auto removedIfaces = msg.unpack<std::set<std::string>>();
    if (!removedIfaces.contains(mctpdEndpointControlInterface))
    {
        return;
    }

    if (auto self = weak.lock())
    {
        self->endpointRemoved();
    }
}

void MctpdDevice::finaliseEndpoint(
    const std::string& objpath, uint8_t eid, int network,
    std::function<void(const std::error_code& ec,
                       const std::shared_ptr<MctpEndpoint>& ep)>&& action)
{
    using namespace sdbusplus::bus::match;
    const auto matchSpec = std::string(rules::interfacesRemoved())
                               .append(rules::argNpath(0, objpath));
    removeMatch = std::make_unique<sdbusplus::bus::match_t>(
        *connection, matchSpec,
        std::bind_front(MctpdDevice::onEndpointInterfacesRemoved,
                        weak_from_this(), objpath));
    endpoint = std::make_shared<MctpdEndpoint>(shared_from_this(), connection,
                                               objpath, network, eid);
    action({}, endpoint);
}

void MctpdDevice::setup(
    std::function<void(const std::error_code& ec,
                       const std::shared_ptr<MctpEndpoint>& ep)>&& action)
{
    auto onSetup = [weak{weak_from_this()}, action{std::move(action)}](
                       const boost::system::error_code& ec, uint8_t eid,
                       int network, const std::string& objpath,
                       bool allocated [[maybe_unused]]) mutable {
        if (ec)
        {
            action(ec, {});
            return;
        }

        if (auto self = weak.lock())
        {
            self->finaliseEndpoint(objpath, eid, network, std::move(action));
        }
    };
    try
    {
        connection->async_method_call(onSetup, mctpdBusName, mctpdControlPath,
                                      mctpdControlInterface, "SetupEndpoint",
                                      interface, physaddr);
    }
    catch (const sdbusplus::exception::SdBusError& err)
    {
        auto errc = std::errc::no_such_device_or_address;
        auto ec = std::make_error_code(errc);
        action(ec, {});
    }
}

void MctpdDevice::endpointRemoved()
{
    if (endpoint)
    {
        removeMatch.reset();
        endpoint->removed();
        endpoint.reset();
    }
}

void MctpdDevice::remove()
{
    if (endpoint)
    {
        endpoint->remove();
    }
}

SmbusMctpdDevice::SmbusMctpdDevice(
    const std::shared_ptr<sdbusplus::asio::connection>& connection, int smbus,
    uint8_t smdev) :
    MctpdDevice(connection, std::string("mctpi2c") + std::to_string(smbus),
                {smdev}),
    smbus(smbus), smdev(smdev)
{}

std::string SmbusMctpdDevice::describe() const
{
    return std::format("bus: {:2}, address: {:#x}", smbus, smdev);
}

MctpdEndpoint::MctpdEndpoint(
    const std::shared_ptr<MctpDevice>& device,
    const std::shared_ptr<sdbusplus::asio::connection>& connection,
    sdbusplus::message::object_path objpath, int network, uint8_t eid) :
    device(device), connection(connection), objpath(std::move(objpath)),
    mctp{network, eid}
{}

void MctpdEndpoint::onMctpEndpointChange(sdbusplus::message_t& msg)
{
    std::string iface;
    std::map<std::string, BasicVariantType> changed;
    std::vector<std::string> invalidated;

    msg.read(iface);
    msg.read(changed);
    msg.read(invalidated);

    if (iface != mctpdEndpointControlInterface)
    {
        return;
    }

    auto it = changed.find("Connectivity");
    if (it == changed.end())
    {
        return;
    }

    updateEndpointConnectivity(std::get<std::string>(it->second));
}

void MctpdEndpoint::updateEndpointConnectivity(const std::string& connectivity)
{
    if (connectivity == "Degraded")
    {
        if (notifyDegraded)
        {
            notifyDegraded(shared_from_this());
        }
    }
    else if (connectivity == "Available")
    {
        if (notifyAvailable)
        {
            notifyAvailable(shared_from_this());
        }
    }
    else
    {
        std::cerr << "Unrecognised connectivity state: '" << connectivity << "'"
                  << std::endl;
    }
}

int MctpdEndpoint::network() const
{
    return mctp.network;
}

uint8_t MctpdEndpoint::eid() const
{
    return mctp.eid;
}

void MctpdEndpoint::subscribe(Event&& degraded, Event&& available,
                              Event&& removed)
{
    const auto matchType = std::string("type='signal'");
    const auto matchMember = std::string("member='PropertiesChanged'");
    const auto pathNamespace = std::string("path_namespace='") + objpath.str +
                               "'";
    const auto arg0Namespace = std::string("arg0namespace='") +
                               mctpdEndpointControlInterface + "'";
    const auto matchSpec = std::string()
                               .append(matchType)
                               .append(",")
                               .append(matchMember)
                               .append(",")
                               .append(pathNamespace)
                               .append(",")
                               .append(arg0Namespace);

    this->notifyDegraded = degraded;
    this->notifyAvailable = available;
    this->notifyRemoved = removed;

    try
    {
        connectivityMatch.emplace(
            static_cast<sdbusplus::bus_t&>(*connection), matchSpec,
            [weak{weak_from_this()}](sdbusplus::message_t& msg) {
            if (auto self = weak.lock())
            {
                self->onMctpEndpointChange(msg);
            }
        });
        connection->async_method_call(
            [weak{weak_from_this()}](const boost::system::error_code& ec,
                                     const std::variant<std::string>& value) {
            if (ec)
            {
                std::cerr << "Failed to get current connectivity state: " << ec
                          << std::endl;
                return;
            }

            if (auto self = weak.lock())
            {
                const std::string& connectivity = std::get<std::string>(value);
                self->updateEndpointConnectivity(connectivity);
            }
        },
            mctpdBusName, objpath.str, "org.freedesktop.DBus.Properties", "Get",
            mctpdEndpointControlInterface, "Connectivity");
    }
    catch (const sdbusplus::exception::SdBusError& err)
    {
        this->notifyDegraded = nullptr;
        this->notifyAvailable = nullptr;
        this->notifyRemoved = nullptr;
        std::throw_with_nested(
            MctpException("Failed to register connectivity signal match"));
    }
}

void MctpdEndpoint::recover()
{
    try
    {
        connection->async_method_call(
            [weak{weak_from_this()}](const boost::system::error_code& ec
                                     [[maybe_unused]]) {
            if (ec)
            {
                if (auto self = weak.lock())
                {
                    std::cerr << "Failed to recover device at '"
                              << self->objpath.str << "'" << std::endl;
                }
            }
        },
            mctpdBusName, objpath.str, mctpdEndpointControlInterface,
            "Recover");
    }
    catch (const sdbusplus::exception::SdBusError& err)
    {
        std::throw_with_nested(
            MctpException("Failed to schedule endpoint recovery"));
    }
}

void MctpdEndpoint::remove()
{
    try
    {
        connection->async_method_call(
            [self{shared_from_this()}](const boost::system::error_code& ec) {
            if (ec)
            {
                std::cerr << "Failed to remove endpoint [" << self->describe()
                          << "]" << std::endl;
                return;
            }
        }, mctpdBusName, objpath.str, mctpdEndpointControlInterface, "Remove");
    }
    catch (const sdbusplus::exception::SdBusError& err)
    {
        std::throw_with_nested(
            MctpException("Failed schedule endpoint removal"));
    }
}

void MctpdEndpoint::removed()
{
    if (notifyRemoved)
    {
        notifyRemoved(shared_from_this());
    }
}

void MctpdEndpoint::setMtu(
    uint32_t mtu, std::function<void(const std::error_code& ec)>&& completed)
{
    try
    {
        connection->async_method_call(
            [cb{std::move(completed)}](const boost::system::error_code& bsec) {
            cb(static_cast<const std::error_code&>(bsec));
        }, mctpdBusName, objpath.str, mctpdEndpointControlInterface, "SetMTU",
            mtu);
    }
    catch (const sdbusplus::exception::SdBusError& err)
    {
        completed(std::error_code(err.get_errno(), std::system_category()));
    }
}

std::string MctpdEndpoint::describe() const
{
    return std::string("network: ")
        .append(std::to_string(mctp.network))
        .append(", EID: ")
        .append(std::to_string(mctp.eid))
        .append(" | ")
        .append(device->describe());
}
