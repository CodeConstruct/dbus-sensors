#pragma once

#include "NVMeDrive.hpp"
#include "NVMeError.hpp"
#include "NVMeSubsys.hpp"
#include "NVMeVolume.hpp"

#include <boost/asio.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <xyz/openbmc_project/Common/Progress/server.hpp>
#include <xyz/openbmc_project/Nvme/CreateVolumeProgressFailure/server.hpp>
#include <xyz/openbmc_project/Nvme/CreateVolumeProgressSuccess/server.hpp>

#include <memory>

class NVMeVolume;

using OperationStatus =
    sdbusplus::xyz::openbmc_project::Common::server::Progress::OperationStatus;
using CreateVolumeProgressSuccess =
    sdbusplus::xyz::openbmc_project::Nvme::server::CreateVolumeProgressSuccess;
using CreateVolumeProgressFailure =
    sdbusplus::xyz::openbmc_project::Nvme::server::CreateVolumeProgressFailure;

class NVMeProgress :
    public sdbusplus::xyz::openbmc_project::Common::server::Progress
{
  public:
    NVMeProgress(std::shared_ptr<sdbusplus::asio::connection> conn,
                 const std::string& path);

    ~NVMeProgress() override;

    void complete();
    void fail();
};

class NVMeCreateVolumeProgress : public NVMeProgress
{
  public:
    NVMeCreateVolumeProgress(std::shared_ptr<sdbusplus::asio::connection> conn,
                             const std::string& path);

    ~NVMeCreateVolumeProgress() override;

    void createSuccess(std::shared_ptr<NVMeVolume> volume);
    void createFailure(nvme_ex_ptr e);

    /* Returns the volume path if successful, or empty otherwise */
    std::string volumePath() const;

    const std::string path;

  private:
    std::shared_ptr<sdbusplus::asio::connection> conn;

    // interfaces are added only once the state is set to success/failure
    std::shared_ptr<CreateVolumeProgressSuccess> success;
    std::shared_ptr<CreateVolumeProgressFailure> failure;
};
