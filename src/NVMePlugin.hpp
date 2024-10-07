#pragma once

#include "Utils.hpp"

#include <libnvme-mi.h>

#include <functional>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>

class NVMeSubsystem;
class NVMeController;

class NVMePlugin;
class NVMeControllerPlugin;

// A map from library name to the dlopen() pointer
extern std::unordered_map<std::string, void*> pluginLibMap;

// entry function for plugin library to create the plugin instance
using createplugin_t = std::shared_ptr<NVMePlugin> (*)(
    std::shared_ptr<NVMeSubsystem> subsys, const SensorData& config);

class NVMeControllerPlugin
{
  public:
    using getlogpage_t = std::function<void(
        uint8_t lid, uint32_t nsid, uint8_t lsp, uint16_t lsi,
        std::function<void(const std::error_code&, std::span<uint8_t>)>&& cb)>;

    // The controller plugin can only be created from NVMePlugin
    NVMeControllerPlugin(std::shared_ptr<NVMeController> cntl,
                         [[maybe_unused]] const SensorData& cfg) :
        nvmeController(cntl)
    {}

    virtual ~NVMeControllerPlugin() {}
    virtual getlogpage_t getGetLogPageHandler()
    {
        return {};
    }

  protected:
    const std::string& getPath() const;
    sdbusplus::asio::object_server& getDbusServer();
    std::shared_ptr<sdbusplus::asio::connection> getDbusConnection();
    boost::asio::io_context& getIOContext();
    bool isPrimary() const;

    /**
     * adminXfer() -  transfer Raw admin cmd to the binded conntroller
     * @admin_req: request header
     * @data: request data payload
     * @timeout_ms: timeout in ms
     * @resp_data_offset: offset into request data to retrieve from controller
     * @cb: callback function after the response received.
     * @ec: error code
     * @admin_resp: response header
     * @resp_data: response data payload
     *
     * Performs an arbitrary NVMe Admin command, using the provided request
     * header, in @admin_req. The requested data is attached by @data, if any.
     *
     * On success, @cb will be called and response header and data are stored
     * in
     * @admin_resp and @resp_data, which has an optional appended payload
     * buffer. The response data does not include the Admin request header, so
     * 0 represents no payload.
     *
     * As with all Admin commands, we can request partial data from the Admin
     * Response payload, offset by @resp_data_offset. In case of resp_data
     * contains only partial data of the caller's requirement, a follow-up
     * call to adminXfer with offset is required.
     *
     * See: &struct nvme_mi_admin_req_hdr and &struct nvme_mi_admin_resp_hdr.
     *
     * @ec will be returned on failure.
     */
    void adminXfer(const nvme_mi_admin_req_hdr& adminReq,
                   std::span<uint8_t> data, unsigned int timeoutMs,
                   std::function<void(const std::error_code& ec,
                                      const nvme_mi_admin_resp_hdr& adminResp,
                                      std::span<uint8_t> respData)>&& cb);
    /**
     * @brief Get cntrl_id for the binded NVMe controller
     *
     * @return cntrl_id
     */
    uint16_t getCntrlId() const;

  private:
    std::shared_ptr<NVMeController> nvmeController;
};

class NVMePlugin
{
  public:
    NVMePlugin(std::shared_ptr<NVMeSubsystem> subsys,
               const SensorData& /*config*/) : subsystem(std::move(subsys)) {};

    virtual ~NVMePlugin() {}

    std::shared_ptr<NVMeControllerPlugin>
        createControllerPlugin(const NVMeController& controller,
                               const SensorData& config);

    // the NVMe subsystem will start the plugin after NVMesubsystem finished
    // intialization and started.
    virtual void start() {}

    // the NVMe subsystem will stop the plugin before NVMe subsystem stop
    // itself.
    virtual void stop() {}

    static constexpr const char* libraryPath = "/usr/lib/nvmed/";

  protected:
    const std::string& getPath() const;
    const std::string& getName() const;
    boost::asio::io_context& getIOContext();
    sdbusplus::asio::object_server& getDbusServer();
    std::shared_ptr<sdbusplus::asio::connection> getDbusConnection();

    const std::map<uint16_t, std::pair<std::shared_ptr<NVMeController>,
                                       std::shared_ptr<NVMeControllerPlugin>>>&
        getControllers();
    // The nvme plugin implemenation need to overload the function to create a
    // derived controller plugin.
    virtual std::shared_ptr<NVMeControllerPlugin>
        makeController(std::shared_ptr<NVMeController> cntl,
                       const SensorData&) = 0;

  private:
    std::shared_ptr<NVMeSubsystem> subsystem;
};
