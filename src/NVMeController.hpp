
#pragma once

#include "NVMeIntf.hpp"
#include "NVMePlugin.hpp"
#include "Utils.hpp"

#include <boost/asio.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <xyz/openbmc_project/Inventory/Item/StorageController/server.hpp>
#include <xyz/openbmc_project/NVMe/NVMeAdmin/server.hpp>
#include <xyz/openbmc_project/Software/ExtendedVersion/server.hpp>
#include <xyz/openbmc_project/Software/Version/server.hpp>

#include <utility>

using SoftwareVersion =
    sdbusplus::xyz::openbmc_project::Software::server::Version;
using SoftwareExtVersion =
    sdbusplus::xyz::openbmc_project::Software::server::ExtendedVersion;

class NVMeSubsystem;

/**
 * @brief A class to represent the NVMeController has not been enabled (CC.EN =
 * 0)
 *
 * The disabled controllers still have cntrl_id and are listed in the
 * cntrl_list. However the functionility has been disabled so neither
 * StorageController nor NVMeAdmin interface should be exposed for the disabled
 * controllers.
 *
 */
class NVMeController
{
  public:
    NVMeController(boost::asio::io_context& io,
                   sdbusplus::asio::object_server& objServer,
                   std::shared_ptr<sdbusplus::asio::connection> conn,
                   std::string path, std::shared_ptr<NVMeMiIntf> nvmeIntf,
                   nvme_mi_ctrl_t ctrl, std::weak_ptr<NVMeSubsystem> subsys);

    virtual ~NVMeController();

    virtual void start(std::shared_ptr<NVMeControllerPlugin> nvmePlugin);
    virtual void stop();

    // set the target as a primary controller with secondary controller list
    // with it
    inline void setPrimary(
        const std::vector<std::shared_ptr<NVMeController>>& secCntrls)
    {
        isPrimary = true;
        setSecAssoc(secCntrls);
    }

    // set the target as a secondary controller
    inline void setSecondary()
    {
        isPrimary = false;
        setSecAssoc({});
    }

    /**
     * @brief Get cntrl_id for the binded NVMe controller
     *
     * @return cntrl_id
     */
    // TODO: replace this with something from libnvme?
    uint16_t getCntrlId() const
    {
        return *reinterpret_cast<uint16_t*>(
            (reinterpret_cast<uint8_t*>(nvmeCtrl) +
             std::max(sizeof(uint16_t), sizeof(void*))));
    }

    /**
     * @brief Get the NVMe controller handle
     */
    nvme_mi_ctrl_t getMiCtrl() const
    {
        return nvmeCtrl;
    }

    /**
     * @brief Update association interface.
     *
     * May be called externally when attached volumes change.
     **/
    void updateAssociation();

  protected:
    friend class NVMeControllerPlugin;

    bool isPrimary;
    boost::asio::io_context& io;
    sdbusplus::asio::object_server& objServer;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    std::string path;

    std::shared_ptr<sdbusplus::asio::dbus_interface> ctrlInterface;
    std::shared_ptr<sdbusplus::asio::dbus_interface> securityInterface;
    std::shared_ptr<sdbusplus::asio::dbus_interface> passthruInterface;

    std::shared_ptr<NVMeMiIntf> nvmeIntf;
    nvme_mi_ctrl_t nvmeCtrl;

    std::shared_ptr<sdbusplus::asio::dbus_interface> assocIntf;
    void createAssociation();
    std::vector<Association> makeAssociation() const;

    // The association to secondary controllers from a primary controller
    std::vector<std::string> secondaryControllers;

    // The parent subsystem
    std::weak_ptr<NVMeSubsystem> subsys;

    // NVMe Plug-in for vendor defined command/field
    std::weak_ptr<NVMeControllerPlugin> plugin;

  private:
    void setSecAssoc(
        const std::vector<std::shared_ptr<NVMeController>>& secCntrls);
};

/**
 * @brief A class for the NVMe controller that has been enabled (CC.EN = 1)
 *
 * The premitted NVMe Admin cmds should be anable to processed via the enabled
 * controller (e.g reading the temletries or other admin tasks). Thus the
 * NVMeAmin and StorageController Dbus interface will be exposed via this class.
 *
 */
class NVMeControllerEnabled :
    public NVMeController,
    //  StorageController interface will be used from PDI once coroutine
    //  sdbusplus methods are added. In the interim it is implemented manually.
    // private sdbusplus::xyz::openbmc_project::Inventory::Item::server::
    //     StorageController,
    private sdbusplus::xyz::openbmc_project::NVMe::server::NVMeAdmin,
    public SoftwareExtVersion,
    public SoftwareVersion,
    public std::enable_shared_from_this<NVMeControllerEnabled>

{
  public:
    static std::shared_ptr<NVMeControllerEnabled>
        create(NVMeController&& nvmeController);

    ~NVMeControllerEnabled() override;

    void start(std::shared_ptr<NVMeControllerPlugin> nvmePlugin) override;
    void stop() override;

  private:
    enum class Status
    {
        Disabled = 0, // the controller is not ready to serve DBus calls
        Enabled = 1,  // the controller is ready to serve DBus calls
    };

    Status status = Status::Disabled;

    NVMeControllerEnabled(NVMeController&& nvmeController);

    void init();

    /* NVMeAdmin method overload */

    /** @brief Implementation for GetLogPage
     *  Send GetLogPage command to NVMe device
     *
     *  @param[in] lid - Log Page Identifier
     *  @param[in] nsid - Namespace Identifier
     *  @param[in] lsp - Log Specific Field
     *  @param[in] lsi - Log Specific Identifier
     *
     *  @return log[sdbusplus::message::unix_fd] - Returned Log Page
     */
    sdbusplus::message::unix_fd getLogPage(uint8_t lid, uint32_t nsid,
                                           uint8_t lsp, uint16_t lsi) override;

    /** @brief Implementation for Identify
     *  Send Identify command to NVMe device
     *
     *  @param[in] cns - Controller or Namespace Structure
     *  @param[in] nsid - Namespace Identifier
     *  @param[in] cntid - Controller Identifier
     *
     *  @return data[sdbusplus::message::unix_fd] - Identify Data
     */
    sdbusplus::message::unix_fd identify(uint8_t cns, uint32_t nsid,
                                         uint16_t cntid) override;
    /** Set value of FirmwareCommitStatus
     * Used to reset the the status back to ready if the commit is not in
     * process.
     */
    NVMeAdmin::FwCommitStatus
        firmwareCommitStatus(NVMeAdmin::FwCommitStatus commitStatus) override;

    /** @brief Implementation for FirmwareCommitAsync
     *  Send Firmware Commit command to NVMe device
     *
     *  @param[in] commitAction - Commit Action defined by NVMe base spec
     * (Figure 175 of rev 1.4)
     *  @param[in] firmwareSlot - Firmware Slot
     *  @param[in] bpid - Boot Partition ID
     */
    void firmwareCommitAsync(uint8_t commitAction, uint8_t firmwareSlot,
                             bool bpid) override;

    /** Set value of FirmwareDownloadStatus
     * Used to reset the the status back to ready if the download is not in
     * process.
     */
    NVMeAdmin::FwDownloadStatus firmwareDownloadStatus(
        NVMeAdmin::FwDownloadStatus downloadStatus) override;

    /** @brief Implementation for FirmwareDownloadAsync
     *  Send Firmware Image to the NVMe device
     *
     *  @param[in] pathToImage - Path to the firmware image
     */
    void firmwareDownloadAsync(std::string pathToImage) override;

    void securitySendMethod(boost::asio::yield_context yield, uint8_t proto,
                            uint16_t protoSpecific, std::span<uint8_t> data);

    std::vector<uint8_t> securityReceiveMethod(boost::asio::yield_context yield,
                                               uint8_t proto,
                                               uint16_t protoSpecific,
                                               uint32_t transferLength);

    std::tuple<uint32_t, uint32_t, uint32_t>
        adminNonDataCmdMethod(boost::asio::yield_context yield, uint8_t opcode,
                              uint32_t cdw1, uint32_t cdw2, uint32_t cdw3,
                              uint32_t cdw10, uint32_t cdw11, uint32_t cdw12,
                              uint32_t cdw13, uint32_t cdw14, uint32_t cdw15);

    void attachVolume(boost::asio::yield_context yield,
                      const sdbusplus::message::object_path& volumePath);

    void detachVolume(boost::asio::yield_context yield,
                      const sdbusplus::message::object_path& volumePath);
};
