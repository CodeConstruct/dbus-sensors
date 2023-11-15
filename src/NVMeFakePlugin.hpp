#include "NVMePlugin.hpp"
#include "Utils.hpp"

class FakePlugin : public NVMePlugin
{
  public:
    FakePlugin(std::shared_ptr<NVMeSubsystem> subsys,
               const SensorData& config) :
        NVMePlugin(subsys, config)
    {
        try
        {
            isPowerOn();
        }
        catch (const std::runtime_error&)
        {}
    }

  private:
    std::shared_ptr<NVMeControllerPlugin>
        makeController(std::shared_ptr<NVMeController> cntl,
                       const SensorData&) override;
};
