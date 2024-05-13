#include "NVMeDevice.hpp"

#include <boost/system/detail/error_code.hpp>

#include <cassert>

void NVMeDevice::start()
{
    subsys->start();

    if (intf.getProtocol() == NVMeIntf::Protocol::NVMeMI)
    {
        setup();
    }
}

void NVMeDevice::setup()
{
    dev->setup(
        [weak{weak_from_this()}](const std::error_code& ec,
                                 const std::shared_ptr<MctpEndpoint>& ep) {
        if (auto self = weak.lock())
        {
            self->finalize(ec, ep);
        }
    });
}

void NVMeDevice::stop()
{
    subsys->stop();
}

void NVMeDevice::finalize(const std::error_code& ec,
                          const std::shared_ptr<MctpEndpoint>& ep)
{
    assert(intf.getProtocol() == NVMeIntf::Protocol::NVMeMI);

    if (ec)
    {
        restart();
        return;
    }

    ep->subscribe(
        [weak{weak_from_this()}](const std::shared_ptr<MctpEndpoint>& ep) {
        if (auto self = weak.lock())
        {
            self->degraded(ep);
        }
    },
        [weak{weak_from_this()}](const std::shared_ptr<MctpEndpoint>& ep) {
        if (auto self = weak.lock())
        {
            self->available(ep);
        }
    },
        // Removed
        [weak{weak_from_this()}](const std::shared_ptr<MctpEndpoint>& ep) {
        if (auto self = weak.lock())
        {
            self->removed(ep);
        }
    });
}

void NVMeDevice::restart()
{
    assert(intf.getProtocol() == NVMeIntf::Protocol::NVMeMI);
    assert(timer);
    assert(gracePeriod);
    // Setup failed, wait a bit and try again
    timer->expires_after(*gracePeriod);
    timer->async_wait(
        [weak{weak_from_this()}](const boost::system::error_code& ec) {
        if (ec)
        {
            return;
        }

        if (auto self = weak.lock())
        {
            self->setup();
        }
    });
}

void NVMeDevice::degraded(const std::shared_ptr<MctpEndpoint>& ep)
{
    assert(intf.getProtocol() == NVMeIntf::Protocol::NVMeMI);
    std::cout << "[" << ep->describe() << "]: Degraded" << std::endl;
    recovering = true;
    timer->cancel();
    std::get<std::shared_ptr<NVMeMiIntf>>(intf.getInferface())->stop();
}

void NVMeDevice::available(const std::shared_ptr<MctpEndpoint>& ep)
{
    assert(intf.getProtocol() == NVMeIntf::Protocol::NVMeMI);
    assert(timer);
    assert(gracePeriod);
    std::cout << subsys->getName() << " [" << ep->describe() << "]: Available"
              << std::endl;

    // The behaviour of MctpEndpoint::subscribe() is to register the provided
    // callbacks, and then fetch the current state of the endpoint. As a
    // consequence of fetching the state, the appropriate callback is be
    // invoked.
    //
    // Unless circumstances are particularly rough, the endpoint will be in the
    // 'Available' state when it is first exposed on DBus.
    //
    // Beyond the start-up entry to the 'Available' state, we will only see an
    // 'Available' event if something has triggered endpoint recovery (putting
    // the endpoint into 'Degraded'), followed by the recovery succeeding.
    //
    // However, it's possible that recovery is triggered by the NVMe MI layer
    // being broken, while the MCTP endpoint continues to respond without error.
    // This can lead to a "tight" event cycle of entering 'Degraded',
    // immediately followed by entering 'Available', where NVMeMi::start() kicks
    // off the endpoint recovery again as the MI layer continues to fail.
    //
    // The impact of this event cycle is exacerbated by `nvme_mi_open_mctp()`
    // performing IO to the device for the purpose of quirk detection. Currently
    // `nvme_mi_open_mctp()` is issued on the main thread, and if the MI
    // layer is dead enough, the device fails to respond to the Admin Identify
    // command. The failure to respond blocks the main thread for the default
    // libnvme-mi command timeout (which, upstream, is 5000ms). This can lead
    // to misbehaviour of applications interacting with the DBus objects exposed
    // by nvmesensor.
    //
    // Mitigate the hazard of this event cycle by enforcing a grace-period after
    // MCTP endpoint recovery succeeds. This can provide some time for other
    // jobs on the main thread to be processed.
    //
    // We track whether the grace period is required via the `recovering`
    // boolean. If we've passed through the 'Degraded' state then we know we're
    // at risk of the tight event cycle, therefore we enforce the grace-period.
    // If we've not passed through 'Degraded' but we have an 'Available' event
    // we know we're in the start-up path, which we don't want to delay.
    if (recovering)
    {
        recovering = false;
        timer->expires_after(*gracePeriod);
        timer->async_wait(
            [weak{weak_from_this()}, ep](const boost::system::error_code& ec) {
            if (ec)
            {
                return;
            }
            if (auto self = weak.lock())
            {
                std::get<std::shared_ptr<NVMeMiIntf>>(self->intf.getInferface())
                    ->start(ep);
            }
        });
    }
    else
    {
        // If we're not recovering we should only see an 'Available' event
        // when we're first initialising the device. There should be no timers
        // to cancel.
        std::size_t cancelled = timer->cancel();
        if (cancelled != 0)
        {
            std::cerr << "[ " << ep->describe()
                      << "]: Unexpected timer cancellation (" << cancelled
                      << ") in non-recovery path!" << std::endl;
        }
        std::get<std::shared_ptr<NVMeMiIntf>>(intf.getInferface())->start(ep);
    }
}

void NVMeDevice::removed(const std::shared_ptr<MctpEndpoint>& ep)
{
    assert(intf.getProtocol() == NVMeIntf::Protocol::NVMeMI);
    std::cout << "[" << ep->describe() << "]: Removed" << std::endl;
    recovering = false;
    std::get<std::shared_ptr<NVMeMiIntf>>(intf.getInferface())->stop();
    restart();
}
