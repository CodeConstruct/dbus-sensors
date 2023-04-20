#include "NVMeController.hpp"

#include "AsioHelper.hpp"
#include "NVMeError.hpp"
#include "NVMePlugin.hpp"

#include <sdbusplus/exception.hpp>
#include <sdbusplus/message/native_types.hpp>
#include <xyz/openbmc_project/Common/File/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>

using sdbusplus::xyz::openbmc_project::Inventory::Item::server::
    StorageController;
using sdbusplus::xyz::openbmc_project::NVMe::server::NVMeAdmin;

std::shared_ptr<NVMeControllerEnabled> NVMeControllerEnabled::create(
    boost::asio::io_context& io, sdbusplus::asio::object_server& objServer,
    std::shared_ptr<sdbusplus::asio::connection> conn, std::string path,
    std::shared_ptr<NVMeMiIntf> nvmeIntf, nvme_mi_ctrl_t ctrl)
{

    auto self = std::shared_ptr<NVMeControllerEnabled>(
        new NVMeControllerEnabled(io, objServer, conn, path, nvmeIntf, ctrl));
    self->init();
    return self;
}

std::shared_ptr<NVMeControllerEnabled>
    NVMeControllerEnabled::create(NVMeController&& nvmeController)
{

    auto self = std::shared_ptr<NVMeControllerEnabled>(
        new NVMeControllerEnabled(std::move(nvmeController)));
    self->init();
    return self;
}

NVMeControllerEnabled::NVMeControllerEnabled(
    boost::asio::io_context& io, sdbusplus::asio::object_server& objServer,
    std::shared_ptr<sdbusplus::asio::connection> conn, std::string path,
    std::shared_ptr<NVMeMiIntf> nvmeIntf, nvme_mi_ctrl_t ctrl) :
    NVMeController(io, objServer, conn, path, nvmeIntf, ctrl),
    StorageController(dynamic_cast<sdbusplus::bus_t&>(*conn), path.c_str()),
    NVMeAdmin(*conn, path.c_str(),
              {{"FirmwareCommitStatus", {FwCommitStatus::Ready}},
              {"FirmwareDownloadStatus", {FwDownloadStatus::Ready}}})
{}

NVMeControllerEnabled::NVMeControllerEnabled(NVMeController&& nvmeController) :
    NVMeController(std::move(nvmeController)),
    StorageController(
        dynamic_cast<sdbusplus::bus_t&>(*this->NVMeController::conn),
        this->NVMeController::path.c_str()),
    NVMeAdmin(*this->NVMeController::conn, this->NVMeController::path.c_str(),
              {{"FirmwareCommitStatus", {FwCommitStatus::Ready}},
              {"FirmwareDownloadStatus", {FwDownloadStatus::Ready}}})
{}

void NVMeControllerEnabled::init()
{
    assocIntf = objServer.add_interface(
        path, "xyz.openbmc_project.Association.Definitions");

    // the association could have be set via NVMeController, set the association
    // dbus property accordingly
    std::vector<Association> associations;
    for (const auto& subsys : subsystems)
    {
        associations.emplace_back("storage", "storage_controller", subsys);
    }

    for (const auto& cntrl : secondaryControllers)
    {
        associations.emplace_back("secondary", "primary", cntrl);
    }

    assocIntf->register_property("Associations", associations);
    assocIntf->initialize();

    passthruInterface =
        objServer.add_interface(path, "xyz.openbmc_project.NVMe.Passthru");

    passthruInterface->register_method(
        "AdminNonDataCmd",
        [selfWeak{weak_from_this()}](
            boost::asio::yield_context yield, uint8_t opcode, uint32_t cdw1,
            uint32_t cdw2, uint32_t cdw3, uint32_t cdw10, uint32_t cdw11,
            uint32_t cdw12, uint32_t cdw13, uint32_t cdw14, uint32_t cdw15) {
        if (selfWeak.expired())
        {
            checkLibNVMeError(std::make_error_code(std::errc::no_such_device),
                              -1, "AdminNonDataCmd");
            return std::tuple<uint32_t, uint32_t, uint32_t>{0, 0, 0};
        }
        return selfWeak.lock()->adminNonDataCmdMethod(yield, opcode, cdw1, cdw2,
                                                      cdw3, cdw10, cdw11, cdw12,
                                                      cdw13, cdw14, cdw15);
    });
    passthruInterface->initialize();

    securityInterface = objServer.add_interface(
        path, "xyz.openbmc_project.Inventory.Item.StorageControllerSecurity");
    securityInterface->register_method(
        "SecuritySend",
        [selfWeak{weak_from_this()}](boost::asio::yield_context yield,
                                     uint8_t proto, uint16_t proto_specific,
                                     std::vector<uint8_t> data) {
        if (selfWeak.expired())
        {
            checkLibNVMeError(std::make_error_code(std::errc::no_such_device),
                              -1, "SecuritySend");
            return;
        }
        return selfWeak.lock()->securitySendMethod(yield, proto, proto_specific,
                                                   data);
        });
    securityInterface->register_method(
        "SecurityReceive",
        [selfWeak{weak_from_this()}](boost::asio::yield_context yield,
                                     uint8_t proto, uint16_t proto_specific,
                                     uint32_t transfer_length) {
        if (selfWeak.expired())
        {
            checkLibNVMeError(std::make_error_code(std::errc::no_such_device),
                              -1, "SecurityReceive");
            return std::vector<uint8_t>{};
        }
        return selfWeak.lock()->securityReceiveMethod(
            yield, proto, proto_specific, transfer_length);
        });

    securityInterface->initialize();

    StorageController::emit_added();
    NVMeAdmin::emit_added();
}

void NVMeControllerEnabled::start(
    std::shared_ptr<NVMeControllerPlugin> nvmePlugin)
{
    this->NVMeController::start(std::move(nvmePlugin));
}

sdbusplus::message::unix_fd NVMeControllerEnabled::getLogPage(uint8_t lid,
                                                              uint32_t nsid,
                                                              uint8_t lsp,
                                                              uint16_t lsi)
{
    std::array<int, 2> pipe;
    if (::pipe(pipe.data()) < 0)
    {
        std::cerr << "GetLogPage fails to open pipe: " << std::strerror(errno)
                  << std::endl;
        throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();
    }

    // standard NVMe Log IDs
    if (lid < uint8_t{0xC0})
    {
        nvmeIntf->adminGetLogPage(
            nvmeCtrl, static_cast<nvme_cmd_get_log_lid>(lid), nsid, lsp, lsi,
            [pipe](const std::error_code& ec, std::span<uint8_t> data) {
            ::close(pipe[0]);
            int fd = pipe[1];
            if (ec)
            {
                std::cerr << "fail to GetLogPage: " << ec.message()
                          << std::endl;
                close(fd);
                return;
            }

            // TODO: evaluate the impact of client not reading fast enough
            // on large trunk of data
            if (::write(fd, data.data(), data.size()) < 0)
            {
                std::cerr << "GetLogPage fails to write fd: "
                          << std::strerror(errno) << std::endl;
            };
            close(fd);
            });
    }
    // vendor Log IDs
    else if (!plugin.expired())
    {
        auto nvmePlugin = plugin.lock();
        auto handler = nvmePlugin->getGetLogPageHandler();
        if (handler)
        {
            std::function<void(const std::error_code&, std::span<uint8_t>)> cb =
                [pipe](std::error_code ec, std::span<uint8_t> data) {
                ::close(pipe[0]);
                int fd = pipe[1];
                if (ec)
                {
                    std::cerr << "fail to GetLogPage: " << ec.message()
                              << std::endl;
                    close(fd);
                    return;
                }

                // TODO: evaluate the impact of client not reading fast enough
                // on large trunk of data
                if (::write(fd, data.data(), data.size()) < 0)
                {
                    std::cerr << "GetLogPage fails to write fd: "
                              << std::strerror(errno) << std::endl;
                };
                close(fd);
            };
            handler(lid, nsid, lsp, lsi, std::move(cb));
        }
        else // No VU LogPage handler
        {
            ::close(pipe[0]);
            ::close(pipe[1]);
            throw sdbusplus::xyz::openbmc_project::Common::Error::
                InvalidArgument();
        }
    }
    else // No VU plugin
    {
        ::close(pipe[0]);
        ::close(pipe[1]);
        throw sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument();
    }
    return sdbusplus::message::unix_fd{pipe[0]};
}

sdbusplus::message::unix_fd
    NVMeControllerEnabled::identify(uint8_t cns, uint32_t nsid, uint16_t cntid)
{
    std::array<int, 2> pipe;
    if (::pipe(pipe.data()) < 0)
    {
        std::cerr << "Identify fails to open pipe: " << std::strerror(errno)
                  << std::endl;
        throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();
    }

    nvmeIntf->adminIdentify(
        nvmeCtrl, static_cast<nvme_identify_cns>(cns), nsid, cntid,
        [self{shared_from_this()}, pipe](const std::error_code& ec,
                                         std::span<uint8_t> data) {
        ::close(pipe[0]);
        int fd = pipe[1];
        if (ec)
        {
            std::cerr << "fail to Identify: " << ec.message() << std::endl;
            close(fd);
            return;
        }
        if (write(fd, data.data(), data.size()) < 0)
        {
            std::cerr << "Identify fails to write fd: " << std::strerror(errno)
                      << std::endl;
        };
        close(fd);
        });
    return sdbusplus::message::unix_fd{pipe[0]};
}

NVMeAdmin::FwCommitStatus NVMeControllerEnabled::firmwareCommitStatus(
    NVMeAdmin::FwCommitStatus status)
{
    auto commitStatus = this->NVMeAdmin::firmwareCommitStatus();
    // The function is only allowed to reset the status back to ready
    if (status != FwCommitStatus::Ready ||
        commitStatus == FwCommitStatus::Ready ||
        commitStatus == FwCommitStatus::InProgress)
    {
        throw sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed{};
    }
    return this->NVMeAdmin::firmwareCommitStatus(status);
}

void NVMeControllerEnabled::firmwareCommitAsync(uint8_t commitAction,
                                                uint8_t firmwareSlot, bool bpid)
{
    auto commitStatus = this->NVMeAdmin::firmwareCommitStatus();
    if (commitStatus != FwCommitStatus::Ready)
    {
        throw sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed();
    }
    this->NVMeAdmin::firmwareCommitStatus(FwCommitStatus::InProgress);
    nvmeIntf->adminFwCommit(
        nvmeCtrl, static_cast<nvme_fw_commit_ca>(commitAction & 0b111),
        firmwareSlot, bpid,
        [self{shared_from_this()}](const std::error_code& ec,
                                   nvme_status_field status) {
        if (ec)
        {
            self->NVMeAdmin::firmwareCommitStatus(FwCommitStatus::Failed);
            return;
        }
        if (status != NVME_SC_SUCCESS)
        {
            self->NVMeAdmin::firmwareCommitStatus(FwCommitStatus::RequireReset);
            return;
        }

        self->NVMeAdmin::firmwareCommitStatus(FwCommitStatus::Success);
        });
}

NVMeAdmin::FwDownloadStatus
    NVMeControllerEnabled::firmwareDownloadStatus(NVMeAdmin::FwDownloadStatus status)
{
    auto downloadStatus = this->NVMeAdmin::firmwareDownloadStatus();
    // The function is only allowed to reset the status back to ready
    if (status != FwDownloadStatus::Ready ||
        downloadStatus == FwDownloadStatus::Ready ||
        downloadStatus == FwDownloadStatus::InProgress)
    {
        throw sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed{};
    }
    return this->NVMeAdmin::firmwareDownloadStatus(status);
}

void NVMeControllerEnabled::firmwareDownloadAsync(std::string pathToImage)
{
    auto downloadStatus = this->NVMeAdmin::firmwareDownloadStatus();
    if (downloadStatus != FwDownloadStatus::Ready)
    {
        throw sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed();
    }
    if (std::filesystem::exists(pathToImage))
    {
        this->NVMeAdmin::firmwareDownloadStatus(FwDownloadStatus::InProgress);
        nvmeIntf->adminFwDownload(
            nvmeCtrl, pathToImage,
            [self{shared_from_this()}](const std::error_code& ec,
                                       nvme_status_field status) {
            if (ec || status != NVME_SC_SUCCESS)
            {
                self->NVMeAdmin::firmwareDownloadStatus(FwDownloadStatus::Failed);
                return;
            }
            self->NVMeAdmin::firmwareDownloadStatus(FwDownloadStatus::Success);
        });
    }
    else
    {
        throw sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument();
    }
}

NVMeControllerEnabled::~NVMeControllerEnabled()
{
    objServer.remove_interface(securityInterface);
    objServer.remove_interface(passthruInterface);
    NVMeAdmin::emit_removed();
    StorageController::emit_removed();
}

NVMeController::NVMeController(
    boost::asio::io_context& io, sdbusplus::asio::object_server& objServer,
    std::shared_ptr<sdbusplus::asio::connection> conn, std::string path,
    std::shared_ptr<NVMeMiIntf> nvmeIntf, nvme_mi_ctrl_t ctrl) :
    io(io),
    objServer(objServer), conn(conn), path(path), nvmeIntf(nvmeIntf),
    nvmeCtrl(ctrl)
{}

NVMeController::~NVMeController()
{
    objServer.remove_interface(assocIntf);
}

void NVMeController::start(std::shared_ptr<NVMeControllerPlugin> nvmePlugin)
{
    plugin = nvmePlugin;
}

void NVMeController::setSecAssoc(
    const std::vector<std::shared_ptr<NVMeController>> secCntrls)
{
    secondaryControllers.clear();

    if (secCntrls.empty())
    {
        return;
    }

    for (const auto& cntrl : secCntrls)
    {
        secondaryControllers.push_back(cntrl->path);
    }

    std::vector<Association> associations;
    for (const auto& subsys : subsystems)
    {
        associations.emplace_back("storage", "storage_controller", subsys);
    }

    for (const auto& cntrl : secondaryControllers)
    {
        associations.emplace_back("secondary", "primary", cntrl);
    }

    if (assocIntf)
    {
        assocIntf->set_property("Associations", associations);
    }
}

void NVMeController::addSubsystemAssociation(const std::string& subsysPath)
{
    subsystems.push_back(subsysPath);

    std::vector<Association> associations;
    for (const auto& subsys : subsystems)
    {
        associations.emplace_back("storage", "storage_controller", subsys);
    }

    for (const auto& cntrl : secondaryControllers)
    {
        associations.emplace_back("secondary", "primary", cntrl);
    }

    if (assocIntf)
    {
        assocIntf->set_property("Associations", associations);
    }
}

void NVMeControllerEnabled::securitySendMethod(boost::asio::yield_context yield,
                                               uint8_t proto,
                                               uint16_t proto_specific,
                                               std::span<uint8_t> data)
{
    using callback_t = void(std::tuple<std::error_code, int>);
    auto [err, nvme_status] =
        boost::asio::async_initiate<boost::asio::yield_context, callback_t>(
            [intf{nvmeIntf}, ctrl{nvmeCtrl}, proto, proto_specific,
             &data](auto&& handler) {
        auto h = asio_helper::CopyableCallback(std::move(handler));

        intf->adminSecuritySend(
            ctrl, proto, proto_specific, data,
            [h](const std::error_code& err, int nvme_status) mutable {
            h(std::make_tuple(err, nvme_status));
            });
            },
            yield);

    // exception must be thrown outside of the async block
    checkLibNVMeError(err, nvme_status, "SecuritySend");
}

std::vector<uint8_t> NVMeControllerEnabled::securityReceiveMethod(
    boost::asio::yield_context yield, uint8_t proto, uint16_t proto_specific,
    uint32_t transfer_length)
{
    using callback_t =
        void(std::tuple<std::error_code, int, std::vector<uint8_t>>);
    auto [err, nvme_status, data] =
        boost::asio::async_initiate<boost::asio::yield_context, callback_t>(
            [intf{nvmeIntf}, ctrl{nvmeCtrl}, proto, proto_specific,
             transfer_length](auto&& handler) {
        auto h = asio_helper::CopyableCallback(std::move(handler));

        intf->adminSecurityReceive(ctrl, proto, proto_specific, transfer_length,
                                   [h](const std::error_code& err,
                                       int nvme_status,
                                       std::span<uint8_t> data) mutable {
            std::vector<uint8_t> d(data.begin(), data.end());
            h(std::make_tuple(err, nvme_status, d));
        });
            },
            yield);

    // exception must be thrown outside of the async block
    checkLibNVMeError(err, nvme_status, "SecurityReceive");
    return data;
}

std::tuple<uint32_t, uint32_t, uint32_t>
    NVMeControllerEnabled::adminNonDataCmdMethod(
        boost::asio::yield_context yield, uint8_t opcode, uint32_t cdw1,
        uint32_t cdw2, uint32_t cdw3, uint32_t cdw10, uint32_t cdw11,
        uint32_t cdw12, uint32_t cdw13, uint32_t cdw14, uint32_t cdw15)
{
    using callback_t = void(std::tuple<std::error_code, int, uint32_t>);
    auto [err, nvme_status, completion_dw0] =
        boost::asio::async_initiate<boost::asio::yield_context, callback_t>(
            [intf{nvmeIntf}, ctrl{nvmeCtrl}, opcode, cdw1, cdw2, cdw3, cdw10,
             cdw11, cdw12, cdw13, cdw14, cdw15](auto&& handler) {
        auto h = asio_helper::CopyableCallback(std::move(handler));

        intf->adminNonDataCmd(ctrl, opcode, cdw1, cdw2, cdw3, cdw10, cdw11,
                              cdw12, cdw13, cdw14, cdw15,
                              [h](const std::error_code& err, int nvme_status,
                                  uint32_t completion_dw0) mutable {
            h(std::make_tuple(err, nvme_status, completion_dw0));
        });
    },
            yield);

    std::cerr << "nvme_status:" << nvme_status << ", dw0:" << completion_dw0
              << std::endl;
    if (nvme_status < 0)
    {
        throw sdbusplus::exception::SdBusError(err.value(),
                                               "adminNonDataCmdMethod");
    }

    // Parse MI status Or MI status from nvme_status
    uint32_t mi_status = 0;
    uint32_t admin_status = 0;
    if (nvme_status_get_type(nvme_status) == NVME_STATUS_TYPE_MI)
    {
        // there is no Admin status and dw0 if MI layer failed.
        mi_status = nvme_status_get_value(nvme_status);
        admin_status = 0;
        completion_dw0 = 0;
    }
    else
    {
        mi_status = 0;
        admin_status = nvme_status_get_value(nvme_status);
    }
    return {mi_status, admin_status, completion_dw0};
}
