#pragma once
#include "AsioWorkPool.hpp"
#include "NVMeBasic.hpp"
#include "NVMeController.hpp"
#include "NVMeDrive.hpp"
#include "NVMeSensor.hpp"
#include "NVMeStorage.hpp"
#include "NVMeUtil.hpp"
#include "Utils.hpp"

class NVMeControllerPlugin;
class NVMePlugin;

class NVMeSubsystem : public std::enable_shared_from_this<NVMeSubsystem>
{
  public:
    static constexpr const char* configType =
        "xyz.openbmc_project.Configuration.NVME1000";

    NVMeSubsystem(boost::asio::io_context& io,
                  sdbusplus::asio::object_server& objServer,
                  std::shared_ptr<sdbusplus::asio::connection> conn,
                  std::shared_ptr<AsioWorkPool> pool, const std::string& path,
                  const std::string& name,
                  const std::shared_ptr<NVMeIntf>& intf);

    void start(const SensorData& configData);

    void stop();

  private:
    friend class NVMePlugin;
    boost::asio::io_context& io;
    sdbusplus::asio::object_server& objServer;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    std::shared_ptr<AsioWorkPool> pool;
    std::string path;
    std::string name;

    std::shared_ptr<NVMeIntf> nvmeIntf;

    // plugin
    std::shared_ptr<NVMePlugin> plugin;

    /* thermal sensor for the subsystem */
    std::shared_ptr<NVMeSensor> ctemp;
    std::shared_ptr<boost::asio::deadline_timer> ctempTimer;

    /*
    Storage interface: xyz.openbmc_project.Inventory.Item.Storage
    */
    NVMeStorage storage;

    /*
    Drive interface: xyz.openbmc_project.Inventory.Item.Drive
    */
    NVMeDrive drive;

    // map from cntrlid to a pair of {controller, controller_plugin}
    std::map<uint16_t, std::pair<std::shared_ptr<NVMeController>,
                                 std::shared_ptr<NVMeControllerPlugin>>>
        controllers{};

    std::vector<Association> associations;
    void createStorageAssociation();
};
