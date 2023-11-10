#include "NVMePlugin.hpp"

class FakePlugin : public NVMePlugin
{
  public:
    FakePlugin(std::shared_ptr<NVMeSubsystem> subsys,
               const SensorData& config) :
        NVMePlugin(subsys, config)
    {}

  private:
    std::shared_ptr<NVMeControllerPlugin>
        makeController(std::shared_ptr<NVMeController> cntl,
                       const SensorData&) override;
};
