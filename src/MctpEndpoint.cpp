#include "MctpEndpoint.hpp"

#include "Utils.hpp"

#include <boost/system/detail/errc.hpp>
#include <sdbusplus/asio/connection.hpp>
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
    connection(connection),
    interface(interface), physaddr(physaddr)
{}

void MctpdDevice::setup(
    std::function<void(const std::error_code& ec,
                       const std::shared_ptr<MctpEndpoint>& ep)>&& action)
{
    try
    {
        connection->async_method_call(
            [weak{weak_from_this()}, action](
                const boost::system::error_code& ec, uint8_t eid, int network,
                const std::string& objpath, bool allocated [[maybe_unused]]) {
            if (ec)
            {
                /* XXX What error does mctpd actually provide? */
                action(ec, {});
                return;
            }

            if (auto self = weak.lock())
            {
                self->endpoint = std::make_shared<MctpdEndpoint>(
                    self->connection, objpath, network, eid);
                action(static_cast<const std::error_code&>(ec), self->endpoint);
            }
        },
            mctpdBusName, mctpdControlPath, mctpdControlInterface,
            "SetupEndpoint", interface, physaddr);
    }
    catch (const sdbusplus::exception::SdBusError& err)
    {
        auto errc = std::errc::no_such_device_or_address;
        auto ec = std::make_error_code(errc);
        action(ec, {});
    }
}

SmbusMctpdDevice::SmbusMctpdDevice(
    const std::shared_ptr<sdbusplus::asio::connection>& connection, int smbus,
    uint8_t smdev) :
    MctpdDevice(connection, std::string("mctpi2c") + std::to_string(smbus),
                {smdev}),
    smbus(smbus), smdev(smdev)
{}

std::string SmbusMctpdDevice::describe()
{
    return std::string("bus: ")
        .append(std::to_string(smbus))
        .append(", address: ")
        .append(std::to_string(smdev));
}

MctpdEndpoint::MctpdEndpoint(
    const std::shared_ptr<sdbusplus::asio::connection>& connection,
    sdbusplus::message::object_path objpath, int network, uint8_t eid) :
    connection(connection),
    objpath(std::move(objpath)), mctp{network, eid}
{}

int MctpdEndpoint::network() const
{
    return mctp.network;
}

uint8_t MctpdEndpoint::eid() const
{
    return mctp.eid;
}

void MctpdEndpoint::setMtu(
    uint32_t mtu, std::function<void(const std::error_code& ec)>&& completed)
{
    try
    {
        connection->async_method_call(
            [cb{std::move(completed)}](const boost::system::error_code& bsec) {
            cb(static_cast<const std::error_code&>(bsec));
        },
            mctpdBusName, objpath.str, mctpdEndpointControlInterface, "SetMTU",
            mtu);
    }
    catch (const sdbusplus::exception::SdBusError& err)
    {
        completed(std::error_code(err.get_errno(), std::system_category()));
    }
}

std::string MctpdEndpoint::describe()
{
    return std::string("network: ")
        .append(std::to_string(mctp.network))
        .append(", EID: ")
        .append(std::to_string(mctp.eid));
}
