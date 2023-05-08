#pragma once

#include <NVMeIntf.hpp>
#include <boost/asio.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <xyz/openbmc_project/Inventory/Item/Drive/server.hpp>
#include <xyz/openbmc_project/Inventory/Item/DriveErase/server.hpp>

#include <memory>

using DriveBase =
    sdbusplus::xyz::openbmc_project::Inventory::Item::server::Drive;
using DriveErase =
    sdbusplus::xyz::openbmc_project::Inventory::Item::server::DriveErase;
using EraseAction = sdbusplus::xyz::openbmc_project::Inventory::Item::server::
    DriveErase::EraseAction;

class NVMeSubsystem;

class NVMeSanitizeParams
{
  public:
    NVMeSanitizeParams(EraseAction sanact);
    auto operator<=>(const NVMeSanitizeParams&) const = default;

    enum nvme_sanitize_sanact nvmeAction() const;

    // returns true if the dword10 (from sanitize log page SCDW10) matches
    // these parameters.
    bool matchesDword10(uint32_t dword10) const;

    EraseAction sanact;

    // for overwrite action
    uint8_t passes;
    uint32_t pattern;
    bool patternInvert;
};

class NVMeDrive :
    public DriveBase,
    public DriveErase,
    public std::enable_shared_from_this<NVMeDrive>
{
  public:
    static const int sanitizePollIntervalSecs = 4;

    NVMeDrive(boost::asio::io_context& io,
              std::shared_ptr<sdbusplus::asio::connection> conn,
              const std::string& path, std::weak_ptr<NVMeSubsystem> subsys);

    ~NVMeDrive() override;

    void erase(EraseAction action) override;

    const std::string path;

  private:
    void sanitizePoll();

    /*
    Parameters of the current/last sanitize operation
    */
    std::optional<NVMeSanitizeParams> sanitizeParams;
    boost::asio::steady_timer sanitizeTimer;
    bool sanitizePollPending = false;

    boost::asio::io_context& io;
    std::weak_ptr<NVMeSubsystem> subsys;
};
