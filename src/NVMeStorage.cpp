#include "NVMeStorage.hpp"

#include "NVMeError.hpp"

RelPerf relativePerformanceFromRP(uint8_t rp)
{
    switch (rp)
    {
        case 0:
            return RelPerf::Best;
        case 1:
            return RelPerf::Better;
        case 2:
            return RelPerf::Good;
        default:
            return RelPerf::Degraded;
    }
}

NVMeStorage::NVMeStorage(sdbusplus::asio::object_server& objServer,
                         sdbusplus::bus_t& bus, const char* path) :
    StorageBase(bus, path),
    objServer(objServer), path(path)
{}

NVMeStorage::~NVMeStorage()
{
    objServer.remove_interface(nvmeStorageInterface);
    emit_removed();
}

void NVMeStorage::init(std::shared_ptr<NVMeStorage> self)
{
    self->nvmeStorageInterface = self->objServer.add_interface(
        self->path, "xyz.openbmc_project.Nvme.Storage");
    self->nvmeStorageInterface->register_method(
        "CreateVolume", [weak{std::weak_ptr<NVMeStorage>(self)}](
                            boost::asio::yield_context yield, uint64_t size,
                            size_t lbaFormat, bool metadataAtEnd) {
        if (auto self = weak.lock())
        {
            return self->createVolume(yield, size, lbaFormat, metadataAtEnd);
        }
        NVMeError::makeInternalError("storage removed")->throw_specific();
    });

    std::vector<std::tuple<size_t, size_t, size_t, RelPerf>> prop;
    self->nvmeStorageInterface->register_property("SupportedFormats", prop);

    self->nvmeStorageInterface->initialize();
    self->emit_added();
}

void NVMeStorage::setSupportedFormats(const std::vector<LBAFormat>& formats)
{
    std::vector<std::tuple<size_t, size_t, size_t, RelPerf>> prop;
    for (auto& f : formats)
    {
        prop.push_back(
            {f.index, f.blockSize, f.metadataSize, f.relativePerformance});
    }
    nvmeStorageInterface->set_property("SupportedFormats", prop);
}
