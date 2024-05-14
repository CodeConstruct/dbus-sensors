#include "NVMeDevice.hpp"

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

    std::get<std::shared_ptr<NVMeMiIntf>>(intf.getInferface())->start(ep);
}

void NVMeDevice::restart()
{
    assert(intf.getProtocol() == NVMeIntf::Protocol::NVMeMI);
    assert(timer);
    // Setup failed, wait a bit and try again
    timer->expires_from_now(std::chrono::seconds(5));
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
    std::get<std::shared_ptr<NVMeMiIntf>>(intf.getInferface())->stop();
}

void NVMeDevice::available(const std::shared_ptr<MctpEndpoint>& ep)
{
    assert(intf.getProtocol() == NVMeIntf::Protocol::NVMeMI);
    std::cout << subsys->getName() << " [" << ep->describe() << "]: Available"
              << std::endl;
    std::get<std::shared_ptr<NVMeMiIntf>>(intf.getInferface())->start(ep);
}

void NVMeDevice::removed(const std::shared_ptr<MctpEndpoint>& ep)
{
    assert(intf.getProtocol() == NVMeIntf::Protocol::NVMeMI);
    std::cout << "[" << ep->describe() << "]: Removed" << std::endl;
    std::get<std::shared_ptr<NVMeMiIntf>>(intf.getInferface())->stop();
    restart();
}
