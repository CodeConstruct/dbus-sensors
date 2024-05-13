#pragma once

#include "MctpEndpoint.hpp"
#include "NVMeIntf.hpp"
#include "NVMeSubsys.hpp"

#include <memory>

class NVMeDevice : public std::enable_shared_from_this<NVMeDevice>
{
    struct Private
    {};

  public:
    static std::shared_ptr<NVMeDevice>
        create(NVMeIntf intf, const std::shared_ptr<NVMeSubsystem>& subsys)
    {
        return std::make_shared<NVMeDevice>(Private(), intf, subsys);
    }

    static std::shared_ptr<NVMeDevice> create(
        boost::asio::io_context& io, const std::shared_ptr<MctpDevice>& dev,
        NVMeIntf intf, const std::shared_ptr<NVMeSubsystem>& subsys,
        std::chrono::duration<long> gracePeriod = std::chrono::seconds(5))
    {
        return std::make_shared<NVMeDevice>(Private(), io, dev, intf, subsys,
                                            gracePeriod);
    }

    NVMeDevice(Private /*unused*/, NVMeIntf intf,
               const std::shared_ptr<NVMeSubsystem>& subsys) :
        intf(intf),
        subsys(subsys)
    {}
    NVMeDevice(Private /*unused*/, boost::asio::io_context& io,
               const std::shared_ptr<MctpDevice>& dev, NVMeIntf intf,
               const std::shared_ptr<NVMeSubsystem>& subsys,
               std::chrono::duration<long> gracePeriod) :
        dev(dev),
        intf(intf), subsys(subsys), timer(io), gracePeriod{gracePeriod}
    {}
    ~NVMeDevice() = default;
    void start();
    void stop();

  private:
    void setup();
    void restart();
    void degraded(const std::shared_ptr<MctpEndpoint>& ep);
    void available(const std::shared_ptr<MctpEndpoint>& ep);
    void removed(const std::shared_ptr<MctpEndpoint>& ep);
    void finalize(const std::error_code& ec,
                  const std::shared_ptr<MctpEndpoint>& ep);

    std::shared_ptr<MctpDevice> dev;
    NVMeIntf intf;
    std::shared_ptr<NVMeSubsystem> subsys;
    std::optional<boost::asio::steady_timer> timer{};
    std::optional<std::chrono::duration<long>> gracePeriod;
    bool recovering{};
};
