#include "NVMeFakePlugin.hpp"

extern "C" std::shared_ptr<NVMePlugin>
    createPlugin(std::shared_ptr<NVMeSubsystem> subsys,
                 const SensorData& config)
{
    return std::make_shared<FakePlugin>(subsys, config);
}

std::shared_ptr<NVMeControllerPlugin>
    FakePlugin::makeController(std::shared_ptr<NVMeController> /* cntl */,
                               const SensorData& /* config */)
{
    return {};
}
