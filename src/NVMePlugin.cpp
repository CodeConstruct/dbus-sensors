#include "NVMePlugin.hpp"

#include "NVMeIntf.hpp"
#include "NVMeSubsys.hpp"
#include "Utils.hpp"

std::shared_ptr<NVMeControllerPlugin>
    NVMePlugin::createControllerPlugin(const NVMeController& controller,
                                       const SensorData& config)
{
    // searching for the target controller in NVMe subsystem
    auto res = subsystem->controllers.find(controller.getCntrlId());
    if (res == subsystem->controllers.end() ||
        &controller != res->second.first.get())
    {
        std::cerr << ("Failed to create controller plugin: "
                      "cannot find the controller")
                  << std::endl;
        res->second.second.reset();
        return {};
    }

    // insert the plugin
    res->second.second = makeController(res->second.first, config);
    return res->second.second;
}

const std::string& NVMePlugin::getPath() const
{
    return subsystem->path;
}

const std::string& NVMePlugin::getName() const
{
    return subsystem->name;
}

boost::asio::io_context& NVMePlugin::getIOContext()
{
    return subsystem->io;
}

sdbusplus::asio::object_server& NVMePlugin::getDbusServer()
{
    return subsystem->objServer;
}

std::shared_ptr<sdbusplus::asio::connection> NVMePlugin::getDbusConnection()
{
    return subsystem->conn;
}

const std::map<uint16_t, std::pair<std::shared_ptr<NVMeController>,
                                   std::shared_ptr<NVMeControllerPlugin>>>&
    NVMePlugin::getControllers()
{
    return subsystem->controllers;
}

const std::string& NVMeControllerPlugin::getPath() const
{
    return nvmeController->path;
}

sdbusplus::asio::object_server& NVMeControllerPlugin::getDbusServer()
{
    return nvmeController->objServer;
}

std::shared_ptr<sdbusplus::asio::connection>
    NVMeControllerPlugin::getDbusConnection()
{
    return nvmeController->conn;
}

boost::asio::io_context& NVMeControllerPlugin::getIOContext()
{
    return nvmeController->io;
}

bool NVMeControllerPlugin::isPrimary() const
{
    return nvmeController->isPrimary;
}

void NVMeControllerPlugin::adminXfer(
    const nvme_mi_admin_req_hdr& admin_req, std::span<uint8_t> data,
    unsigned int timeout_ms,
    std::function<void(const std::error_code& ec,
                       const nvme_mi_admin_resp_hdr& admin_resp,
                       std::span<uint8_t> resp_data)>&& cb)
{
    nvmeController->nvmeIntf->adminXfer(nvmeController->nvmeCtrl, admin_req,
                                        data, timeout_ms, std::move(cb));
}

uint16_t NVMeControllerPlugin::getCntrlId() const
{
    return nvmeController->getCntrlId();
}
