#include "NVMeProgress.hpp"

using sdbusplus::xyz::openbmc_project::Common::server::Progress;

NVMeProgress::NVMeProgress(std::shared_ptr<sdbusplus::asio::connection> conn,
                           const std::string& path) :
    Progress(dynamic_cast<sdbusplus::bus_t&>(*conn), path.c_str())
{
    uint64_t usec = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
    startTime(usec, true);

    Progress::emit_added();
}

NVMeProgress::~NVMeProgress()
{
    Progress::emit_removed();
}

void NVMeProgress::complete()
{
    uint64_t usec = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
    completedTime(usec);
    status(OperationStatus::Completed);
}

void NVMeProgress::fail()
{
    // TODO: perhaps errorName could be a general NVMeProgress property.
    status(OperationStatus::Failed);
}

NVMeCreateVolumeProgress::NVMeCreateVolumeProgress(
    std::shared_ptr<sdbusplus::asio::connection> conn,
    const std::string& path) :
    NVMeProgress(conn, path),
    conn(conn), path(path)
{}

NVMeCreateVolumeProgress::~NVMeCreateVolumeProgress()
{
    // TODO
    if (success)
    {
        success->emit_removed();
    }
    if (failure)
    {
        failure->emit_removed();
    }
}

void NVMeCreateVolumeProgress::createSuccess(std::shared_ptr<NVMeVolume> volume)
{
    success = std::make_shared<CreateVolumeProgressSuccess>(
        dynamic_cast<sdbusplus::bus_t&>(*conn), path.c_str());
    success->volumePath(volume->path);
    success->emit_added();
    complete();
}

void NVMeCreateVolumeProgress::createFailure(nvme_ex_ptr e)
{
    failure = std::make_shared<CreateVolumeProgressFailure>(
        dynamic_cast<sdbusplus::bus_t&>(*conn), path.c_str());
    failure->errorName(e->name());
    failure->errorDescription(e->description());
    failure->emit_added();
    fail();
}

std::string NVMeCreateVolumeProgress::volumePath() const
{
    if (success)
    {
        return success->volumePath();
    }
    else
    {
        return "";
    }
}
