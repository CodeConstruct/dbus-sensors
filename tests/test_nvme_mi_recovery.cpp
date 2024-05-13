#include "NVMeDevice.hpp"
#include "NVMeIntf.hpp"
#include "NVMeMi.hpp"
#include "NVMeSubsys.hpp"
#include "Utils.hpp"

#include <boost/asio/steady_timer.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

class MockMctpEndpoint : public MctpEndpoint
{
  public:
    MOCK_METHOD(int, network, (), (const, override));
    MOCK_METHOD(uint8_t, eid, (), (const, override));
    MOCK_METHOD(void, subscribe,
                (MctpEndpoint::Event && degraded,
                 MctpEndpoint::Event&& available,
                 MctpEndpoint::Event&& removed),
                (override));
    MOCK_METHOD(void, setMtu,
                (uint32_t mtu,
                 std::function<void(const std::error_code& ec)>&& completed),
                (override));
    MOCK_METHOD(void, remove, (), (override));
    MOCK_METHOD(void, recover, (), (override));
    MOCK_METHOD(std::string, describe, (), (const, override));
};

class MockMctpDevice : public MctpDevice
{
  public:
    MOCK_METHOD(void, setup,
                (std::function<void(const std::error_code& ec,
                                    const std::shared_ptr<MctpEndpoint>& ep)> &&
                 action),
                (override));
    MOCK_METHOD(void, remove, (), (override));
    MOCK_METHOD(std::string, describe, (), (const, override));
};

TEST(NVMeRecovery, optimisationFailure)
{
    boost::asio::io_context io;

    auto mctpEp = std::make_shared<MockMctpEndpoint>();
    EXPECT_CALL(*mctpEp, describe())
        .WillRepeatedly(testing::Return("Mock MCTP Endpoint"));
    EXPECT_CALL(*mctpEp, eid()).WillRepeatedly(testing::Return(9));
    EXPECT_CALL(*mctpEp, network()).WillRepeatedly(testing::Return(1));

    MctpEndpoint::Event degradedHandler;
    MctpEndpoint::Event availableHandler;
    MctpEndpoint::Event removedHandler;
    EXPECT_CALL(*mctpEp, subscribe(testing::_, testing::_, testing::_))
        .WillOnce(testing::DoAll(testing::SaveArg<0>(&degradedHandler),
                                 testing::SaveArg<1>(&availableHandler),
                                 testing::SaveArg<2>(&removedHandler),
                                 testing::InvokeWithoutArgs([&]() {
        io.post([&]() { availableHandler(mctpEp); });
    })));
    EXPECT_CALL(*mctpEp, recover())
        .Times(testing::Between(1, 3))
        .WillRepeatedly(testing::InvokeWithoutArgs([&]() {
        io.post([&]() { degradedHandler(mctpEp); });
        io.post([&]() { availableHandler(mctpEp); });
    }));

    auto mctpDev = std::make_shared<MockMctpDevice>();
    EXPECT_CALL(*mctpDev, describe())
        .WillRepeatedly(testing::Return("Mock MCTP Device"));
    EXPECT_CALL(*mctpDev, setup(testing::_))
        .WillOnce(testing::InvokeArgument<0>(std::error_code(), mctpEp));

    auto systemBus = std::make_shared<sdbusplus::asio::connection>(io);
    sdbusplus::asio::object_server objectServer(systemBus, true);
    auto worker = std::make_shared<NVMeMiWorker>();
    auto intf = NVMeIntf::create<NVMeMi>(io, systemBus, mctpDev, worker);
    SensorData sensorData{};
    auto subsys = NVMeSubsystem::create(io, objectServer, systemBus, "/foo",
                                        "bar", sensorData, intf);
    auto nvmeDev = NVMeDevice::create(io, mctpDev, std::move(intf), subsys,
                                      std::chrono::seconds(2));
    nvmeDev->start();
    io.run_for(std::chrono::seconds(6));
    nvmeDev->stop();
    io.run_for(std::chrono::seconds(1));

    // https://stackoverflow.com/a/10289205
    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(mctpEp.get()));
    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(mctpDev.get()));
}

// Unused, but required to link successfully
std::unordered_map<std::string, void*> pluginLibMap = {};

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
