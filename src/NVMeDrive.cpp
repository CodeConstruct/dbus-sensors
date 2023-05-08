#include "NVMeDrive.hpp"

#include "NVMeError.hpp"
#include "NVMeSubsys.hpp"

#include <iostream>

NVMeDrive::NVMeDrive(boost::asio::io_context& io,
                     std::shared_ptr<sdbusplus::asio::connection> conn,
                     const std::string& path,
                     std::weak_ptr<NVMeSubsystem> subsys) :
    DriveBase(dynamic_cast<sdbusplus::bus_t&>(*conn), path.c_str()),
    DriveErase(dynamic_cast<sdbusplus::bus_t&>(*conn), path.c_str()),
    path(path), sanitizeTimer(io), io(io), subsys(subsys)
{
    DriveBase::emit_added();
    DriveErase::emit_added();
}

NVMeDrive::~NVMeDrive()
{
    sanitizeTimer.cancel();
    DriveErase::emit_removed();
    DriveBase::emit_removed();
}

// DriveErase.Erase method handler
void NVMeDrive::erase(EraseAction action)
{
    std::shared_ptr<NVMeSubsystem> s = subsys.lock();
    if (!s)
    {
        throw std::runtime_error("Sanitize called while shutting down");
    }

    NVMeSanitizeParams params(action);

    if (eraseInProgress())
    {
        // Already running
        if (params == sanitizeParams)
        {
            return;
        }
        else
        {
            throw *makeLibNVMeError(
                "sanitize already in progress with different parameters",
                std::make_shared<CommonErr::Unavailable>());
        }
    }
    else
    {
        sanitizeParams = params;
    }

    // Clear properties
    erasePercentage(0.0);
    errorName("");
    errorDescription("");
    // eraseInProgress() should always be set last.
    eraseInProgress(true);

    s->startSanitize(params, [self{shared_from_this()}](nvme_ex_ptr ex) {
        if (ex)
        {
            // Update properties with the submission failure
            self->erasePercentage(0.0);
            self->errorName(ex->name());
            self->errorDescription(ex->description());
            self->eraseInProgress(false);
        }
        else
        {
            // start the timer
            self->sanitizePoll();
        }
    });
}

void NVMeDrive::sanitizePoll()
{
    if (sanitizePollPending)
    {
        return;
    }
    sanitizePollPending = true;
    sanitizeTimer.expires_after(std::chrono::seconds(sanitizePollIntervalSecs));
    sanitizeTimer.async_wait(
        [weak{weak_from_this()}](boost::system::error_code ec) {
        if (ec == boost::asio::error::operation_aborted)
        {
            return;
        }

        auto self = weak.lock();
        if (!self)
        {
            return;
        }
        std::shared_ptr<NVMeSubsystem> s = self->subsys.lock();
        if (!s)
        {
            return;
        }

        self->sanitizePollPending = false;

        if (self->eraseInProgress())
        {
            s->sanitizeStatus(
                [self](nvme_ex_ptr ex, bool inProgress, bool failed,
                       bool completed, uint16_t sstat, uint16_t sprog,
                       uint32_t scdw10) {
                (void)sstat;
                (void)sprog;
                (void)scdw10;
                if (ex)
                {
                    std::cerr << "Error returned reading sanitize log: " << ex
                              << std::endl;
                }
                else
                {
                    if (completed)
                    {
                        self->erasePercentage(0.0);
                        self->eraseInProgress(false);
                    }
                    else if (failed)
                    {
                        self->erasePercentage(0.0);
                        self->eraseInProgress(false);
                        self->errorName(
                            CommonErr::DeviceOperationFailed::errName);
                        self->errorDescription("Sanitize operation failed");
                    }
                    else if (inProgress)
                    {
                        self->erasePercentage(100.0 * sprog / 0x10000);
                    }
                }

                if (self->eraseInProgress())
                {
                    self->sanitizePoll();
                }
            });
        }
    });
}

NVMeSanitizeParams::NVMeSanitizeParams(EraseAction sanact) :
    sanact(sanact), passes(1), pattern(0x0), patternInvert(0)
{}

enum nvme_sanitize_sanact NVMeSanitizeParams::nvmeAction() const
{
    switch (sanact)
    {
        case EraseAction::BlockErase:
            return NVME_SANITIZE_SANACT_START_BLOCK_ERASE;
        case EraseAction::CryptoErase:
            return NVME_SANITIZE_SANACT_START_CRYPTO_ERASE;
        case EraseAction::Overwrite:
            return NVME_SANITIZE_SANACT_START_OVERWRITE;
    }
    throw std::logic_error("unreachable");
}

bool NVMeSanitizeParams::matchesDword10(uint32_t dword10) const
{
    uint32_t own_dword10 = 0;

    // reconstruct the dword10 sent by libnvme
    own_dword10 |= (uint32_t)nvmeAction();
    own_dword10 |= (((uint32_t)patternInvert) << 8);
    own_dword10 |= (((uint32_t)passes & 0xf) << 4);

    return dword10 == own_dword10;
}
