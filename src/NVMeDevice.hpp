#pragma once

#include "MctpEndpoint.hpp"
#include "NVMeIntf.hpp"
#include "NVMeSubsys.hpp"

class NVMeDevice
{
  public:
    NVMeDevice(const std::shared_ptr<MctpDevice>& dev, NVMeIntf&& intf,
               const std::shared_ptr<NVMeSubsystem>& subsys) :
        dev(dev),
        intf(intf), subsys(subsys)
    {}
    ~NVMeDevice() = default;
    void start(const std::shared_ptr<boost::asio::steady_timer>& timer);
    void stop();

  private:
    std::shared_ptr<MctpDevice> dev;
    NVMeIntf intf;
    std::shared_ptr<NVMeSubsystem> subsys;
};
