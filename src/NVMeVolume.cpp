#include "NVMeVolume.hpp"

NVMeVolume::NVMeVolume(sdbusplus::asio::object_server& objServer,
                       std::shared_ptr<sdbusplus::asio::connection> conn,
                       std::shared_ptr<NVMeSubsystem> subsys, uint32_t nsid) :
    VolumeBase(dynamic_cast<sdbusplus::bus_t&>(*conn),
               subsys->volumePath(nsid).c_str()),
    NvmeVolumeBase(dynamic_cast<sdbusplus::bus_t&>(*conn),
                   subsys->volumePath(nsid).c_str()),
    path(subsys->volumePath(nsid)), objServer(objServer), subsys(subsys)
{
    namespaceId(nsid, false);
    // see init()
}

void NVMeVolume::init()
{
    deleteInterface =
        objServer.add_interface(path, "xyz.openbmc_project.Object.Delete");
    deleteInterface->register_method(
        "Delete", [weak{weak_from_this()}](boost::asio::yield_context yield) {
            auto self = weak.lock();
            if (!self)
            {
                throw std::runtime_error("volume delete called twice?");
            }
            auto subsys = self->subsys.lock();
            if (!subsys)
            {
                throw std::runtime_error("nvmesensor is shutting down");
            }
            subsys->deleteVolume(yield, self);
        });
    deleteInterface->initialize();

    VolumeBase::emit_added();
    NvmeVolumeBase::emit_added();
}

std::shared_ptr<NVMeVolume>
    NVMeVolume::create(sdbusplus::asio::object_server& objServer,
                       std::shared_ptr<sdbusplus::asio::connection> conn,
                       std::shared_ptr<NVMeSubsystem> subsys, uint32_t nsid)
{
    auto self = std::shared_ptr<NVMeVolume>(
        new NVMeVolume(objServer, conn, subsys, nsid));
    self->init();
    return self;
}

NVMeVolume::~NVMeVolume()
{
    NvmeVolumeBase::emit_removed();
    VolumeBase::emit_removed();
    objServer.remove_interface(deleteInterface);
}

void NVMeVolume::erase(VolumeBase::EraseMethod eraseType)
{
    (void)eraseType;
    // TODO: will need dbus async method handling.
    throw std::runtime_error("volume erase not yet implemented");
}

// Additional methods on Volume that are not relevant.

void NVMeVolume::formatLuks(std::vector<uint8_t>, VolumeBase::FilesystemType)
{
    throw std::runtime_error("Method Not Supported");
}

void NVMeVolume::lock()
{
    throw std::runtime_error("Method Not Supported");
}

void NVMeVolume::unlock(std::vector<uint8_t>)
{
    throw std::runtime_error("Method Not Supported");
}

void NVMeVolume::changePassword(std::vector<uint8_t>, std::vector<uint8_t>)
{
    throw std::runtime_error("Method Not Supported");
}
