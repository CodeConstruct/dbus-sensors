#pragma once
#include "NVMeBasic.hpp"
#include "NVMeController.hpp"
#include "NVMeDrive.hpp"
#include "NVMeProgress.hpp"
#include "NVMeSensor.hpp"
#include "NVMeStorage.hpp"
#include "NVMeUtil.hpp"
#include "Utils.hpp"

class NVMeControllerPlugin;
class NVMePlugin;
class NVMeVolume;
class NVMeCreateVolumeProgress;

class NVMeSubsystem :
    public std::enable_shared_from_this<NVMeSubsystem>,
    public NVMeStorage
{
  public:
    static constexpr const char* sensorType = "NVME1000";

    static std::shared_ptr<NVMeSubsystem>
        create(boost::asio::io_context& io,
               sdbusplus::asio::object_server& objServer,
               std::shared_ptr<sdbusplus::asio::connection> conn,
               const std::string& path, const std::string& name,
               const SensorData& configData, NVMeIntf intf);

    ~NVMeSubsystem();

    void start();

    void stop();

    /** @brief Returns the dbus path for a given volume.
     *
     *  @param[in] nsid - The NSID of the volume
     *
     *  @return path[std::string] - The dbus path for the volume.
     */
    std::string volumePath(uint32_t nsid) const;

    void deleteVolume(boost::asio::yield_context yield,
                      std::shared_ptr<NVMeVolume> volume);

    std::vector<uint32_t> attachedVolumes(uint16_t ctrlId) const;
    void attachCtrlVolume(uint16_t ctrlId, uint32_t nsid);
    void detachCtrlVolume(uint16_t ctrlId, uint32_t nsid);
    void detachAllCtrlVolume(uint32_t nsid);
    std::shared_ptr<NVMeVolume>
        getVolume(const sdbusplus::message::object_path& volPath) const;

    void startSanitize(const NVMeSanitizeParams& params,
                       std::function<void(nvme_ex_ptr ex)>&& submitCb);
    void sanitizeStatus(
        std::function<void(nvme_ex_ptr ex, bool inProgress, bool failed,
                           bool completed, uint16_t sstat, uint16_t sprog,
                           uint32_t scdw10)>&& cb);

    const std::string path;

  public:
    NVMeSubsystem(boost::asio::io_context& io,
                  sdbusplus::asio::object_server& objServer,
                  std::shared_ptr<sdbusplus::asio::connection> conn,
                  const std::string& path, const std::string& name,
                  const SensorData& configData, NVMeIntf intf);

    void init();

  private:
    friend class NVMePlugin;
    boost::asio::io_context& io;
    sdbusplus::asio::object_server& objServer;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    std::string name;
    SensorData config;

    NVMeIntf nvmeIntf;

    enum class Status
    {
        Stop,
        Intiatilzing,
        Start,
    };

    Status status;

    // plugin
    std::shared_ptr<NVMePlugin> plugin;

    /* thermal sensor for the subsystem */
    std::shared_ptr<NVMeSensor> ctemp;
    std::shared_ptr<boost::asio::steady_timer> ctempTimer;

    /*
    Drive interface: xyz.openbmc_project.Inventory.Item.Drive
    */
    std::shared_ptr<NVMeDrive> drive;

    // map from cntrlid to a pair of {controller, controller_plugin}
    std::map<uint16_t, std::pair<std::shared_ptr<NVMeController>,
                                 std::shared_ptr<NVMeControllerPlugin>>>
        controllers{};

    /*
    map of nsid to volumes
    */
    std::map<uint32_t, std::shared_ptr<NVMeVolume>> volumes;

    /*
     * volumes attached to controllers
     */
    std::map<uint16_t, std::set<uint32_t>> attached;

    /*
    In-progress or completed create operations
    */
    std::unordered_map<std::string, std::shared_ptr<NVMeCreateVolumeProgress>>
        createProgress;

    // controller to use for NVMe operations. Is a member of the controllers
    // map.
    std::shared_ptr<NVMeControllerEnabled> primaryController;

    std::shared_ptr<sdbusplus::asio::dbus_interface> assocIntf;
    void createAssociation();
    void updateAssociation();
    std::vector<Association> makeAssociation() const;

    // make the subsystem functional/functional be enabling/disabling the
    // storage controller, namespaces and thermal sensors.
    void markFunctional(bool toggle);

    // mark the availability of the Storage device.
    void markAvailable(bool toggle);

    void fallbackNoSecondary();

    sdbusplus::message::object_path
        createVolume(boost::asio::yield_context yield, uint64_t size,
                     size_t lbaFormat, bool metadataAtEnd) override;

    // callback when drive completes. not called in dbus method context.
    void createVolumeFinished(std::string prog_id, nvme_ex_ptr ex,
                              NVMeNSIdentify ns);

    void addIdentifyNamespace(uint32_t nsid);

    void fillDrive();
    void updateVolumes();

    // removes state associated with the volume. Does not manipulate the drive.
    void forgetVolume(std::shared_ptr<NVMeVolume> volume);

    // adds state associated with the volume. Does not create a volume.
    // may throw if the volume exists.
    std::shared_ptr<NVMeVolume> addVolume(const NVMeNSIdentify& ns);

    void querySupportedFormats();

    // a counter to skip health poll when NVMe subsystem becomes Unavailable
    unsigned UnavailableCount = 0;
    static constexpr unsigned UnavailableMaxCount = 60;

    // process Secondary controller and start controllers and the associated
    // Plugin
    void processSecondaryControllerList(nvme_secondary_ctrl_list* secCntlrList);
};
