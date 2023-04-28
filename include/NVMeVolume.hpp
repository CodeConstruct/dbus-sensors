#pragma once

#include "NVMeSubsys.hpp"

#include <boost/asio.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <xyz/openbmc_project/Inventory/Item/Volume/server.hpp>
#include <xyz/openbmc_project/Nvme/Volume/server.hpp>

#include <memory>

using VolumeBase =
    sdbusplus::xyz::openbmc_project::Inventory::Item::server::Volume;
using NvmeVolumeBase = sdbusplus::xyz::openbmc_project::Nvme::server::Volume;

class NVMeSubsystem;

// Object.Delete implemented manually at present, to allow async method call
// for .Delete

// using DeleteBase =
//     sdbusplus::xyz::openbmc_project::Object::server::Delete;

class NVMeVolume :
    public VolumeBase,
    public NvmeVolumeBase,
    public std::enable_shared_from_this<NVMeVolume>
{
  public:
    static std::shared_ptr<NVMeVolume>
        create(sdbusplus::asio::object_server& objServer,
               std::shared_ptr<sdbusplus::asio::connection> conn,
               std::shared_ptr<NVMeSubsystem> subsys, uint32_t nsid);
    ~NVMeVolume() override;

    const std::string path;

  private:
    NVMeVolume(sdbusplus::asio::object_server& objServer,
               std::shared_ptr<sdbusplus::asio::connection> conn,
               std::shared_ptr<NVMeSubsystem> subsys, uint32_t nsid);
    void init();

    void formatLuks(std::vector<uint8_t> password,
                    VolumeBase::FilesystemType type) override;

    void erase(VolumeBase::EraseMethod eraseType) override;

    void lock() override;

    void unlock(std::vector<uint8_t> password) override;

    void changePassword(std::vector<uint8_t> oldPassword,
                        std::vector<uint8_t> newPassword) override;

    std::shared_ptr<sdbusplus::asio::dbus_interface> deleteInterface;

    sdbusplus::asio::object_server& objServer;

    std::weak_ptr<NVMeSubsystem> subsys;
};
