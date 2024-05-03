#include "NVMeDevice.hpp"

static void
    setupMctpDevice(const std::shared_ptr<MctpDevice>& dev,
                    const std::weak_ptr<NVMeMiIntf>& weakIntf,
                    const std::weak_ptr<NVMeSubsystem>& weakSubsys,
                    const std::shared_ptr<boost::asio::steady_timer>& timer)
{
    dev->setup([weakDev{std::weak_ptr(dev)}, weakIntf, weakSubsys,
                timer](const std::error_code& ec,
                       const std::shared_ptr<MctpEndpoint>& ep) {
        if (ec)
        {
            auto dev = weakDev.lock();
            if (!dev)
            {
                return;
            }
            // Setup failed, wait a bit and try again
            timer->expires_from_now(std::chrono::seconds(5));
            timer->async_wait([=](const boost::system::error_code& ec) {
                if (!ec)
                {
                    setupMctpDevice(dev, weakIntf, weakSubsys, timer);
                }
            });
            return;
        }

        ep->subscribe(
            // Degraded
            [weakIntf](const std::shared_ptr<MctpEndpoint>& ep) {
            if (auto miIntf = weakIntf.lock())
            {
                std::cout << "[" << ep->describe() << "]: Degraded"
                          << std::endl;
                miIntf->stop();
            }
        },
            // Available
            [weakIntf, weakSubsys](const std::shared_ptr<MctpEndpoint>& ep) {
            if (auto miIntf = weakIntf.lock())
            {
                if (auto subsys = weakSubsys.lock())
                {
                    std::cout << subsys->getName() << " [" << ep->describe()
                              << "]: Available" << std::endl;
                }
                miIntf->start(ep);
            }
        },
            // Removed
            [=](const std::shared_ptr<MctpEndpoint>& ep) {
            auto nvmeSubsys = weakSubsys.lock();
            auto miIntf = weakIntf.lock();
            auto dev = weakDev.lock();
            if (!nvmeSubsys || !miIntf || !dev)
            {
                return;
            }

            std::cout << "[" << ep->describe() << "]: Removed" << std::endl;
            miIntf->stop();
            // Start polling for the return of the device
            timer->expires_from_now(std::chrono::seconds(5));
            timer->async_wait([=](const boost::system::error_code& ec) {
                if (!ec)
                {
                    setupMctpDevice(dev, weakIntf, weakSubsys, timer);
                }
            });
        });

        auto miIntf = weakIntf.lock();
        auto nvmeSubsys = weakSubsys.lock();
        if (miIntf && nvmeSubsys)
        {
            miIntf->start(ep);
        }
    });
};

void NVMeDevice::start(const std::shared_ptr<boost::asio::steady_timer>& timer)
{
    if (intf.getProtocol() != NVMeIntf::Protocol::NVMeMI)
    {
        return;
    }

    setupMctpDevice(dev,
                    std::get<std::shared_ptr<NVMeMiIntf>>(intf.getInferface()),
                    subsys, timer);
}

void NVMeDevice::stop()
{
    subsys->stop();
}
