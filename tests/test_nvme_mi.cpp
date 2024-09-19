#include "NVMeMiFake.hpp"
#include "NVMeSubsys.hpp"

#include <dlfcn.h>
#include <valgrind/valgrind.h>

#include <nlohmann/json.hpp>
#include <sdbusplus/asio/connection.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#define xstr(s) str(s)
#define str(s) #s

std::unordered_map<std::string, void*> pluginLibMap = {};
class NVMeMiMock :
    public NVMeMiIntf,
    public std::enable_shared_from_this<NVMeMiMock>
{
  public:
    NVMeMiMock(boost::asio::io_context& io, std::chrono::milliseconds delay) :
        fake(std::move(std::make_shared<NVMeMiFake>(io, delay)))
    {
        ON_CALL(*this, getNID).WillByDefault([]() { return 0; });
        ON_CALL(*this, getEID).WillByDefault([]() { return 0; });
        ON_CALL(*this, miSubsystemHealthStatusPoll)
            .WillByDefault(
                [this](
                    std::function<void(const std::error_code&,
                                       nvme_mi_nvm_ss_health_status*)>&& cb) {
            return fake->miSubsystemHealthStatusPoll(std::move(cb));
        });
        ON_CALL(*this, miScanCtrl)
            .WillByDefault(
                [this](
                    std::function<void(const std::error_code& ec,
                                       const std::vector<nvme_mi_ctrl_t>& list)>
                        cb) { return fake->miScanCtrl(std::move(cb)); });
        ON_CALL(*this, flushOperations)
            .WillByDefault([this](std::function<void()>&& cb) {
            return fake->flushOperations(std::move(cb));
        });
        ON_CALL(*this, adminIdentify)
            .WillByDefault(
                [this](
                    nvme_mi_ctrl_t ctrl, nvme_identify_cns cns, uint32_t nsid,
                    uint16_t cntid,
                    std::function<void(nvme_ex_ptr, std::span<uint8_t>)>&& cb) {
            return fake->adminIdentify(ctrl, cns, nsid, cntid, std::move(cb));
        });
        ON_CALL(*this, adminGetLogPage)
            .WillByDefault(
                [this](nvme_mi_ctrl_t ctrl, nvme_cmd_get_log_lid lid,
                       uint32_t nsid, uint8_t lsp, uint16_t lsi,
                       std::function<void(const std::error_code&,
                                          std::span<uint8_t>)>&& cb) {
            return fake->adminGetLogPage(ctrl, lid, nsid, lsp, lsi,
                                         std::move(cb));
        });
        ON_CALL(*this, adminFwCommit)
            .WillByDefault([this](nvme_mi_ctrl_t ctrl, nvme_fw_commit_ca action,
                                  uint8_t slot, bool bpid,
                                  std::function<void(const std::error_code&,
                                                     nvme_status_field)>&& cb) {
            return fake->adminFwCommit(ctrl, action, slot, bpid, std::move(cb));
        });
        ON_CALL(*this, adminXfer)
            .WillByDefault(
                [this](
                    nvme_mi_ctrl_t ctrl, const nvme_mi_admin_req_hdr& admin_req,
                    std::span<uint8_t> data, unsigned int timeout_ms,
                    std::function<void(const std::error_code& ec,
                                       const nvme_mi_admin_resp_hdr& admin_resp,
                                       std::span<uint8_t> resp_data)>&& cb) {
            return fake->adminXfer(ctrl, admin_req, data, timeout_ms,
                                   std::move(cb));
        });
        ON_CALL(*this, adminSecuritySend).WillByDefault([]() { return; });
        ON_CALL(*this, adminSecurityReceive).WillByDefault([]() { return; });
        ON_CALL(*this, adminListNamespaces)
            .WillByDefault(
                [this](nvme_mi_ctrl_t ctrl,
                       std::function<void(nvme_ex_ptr ex,
                                          std::vector<uint32_t> ns)>&& cb) {
            // return empty NS list
            return fake->adminListNamespaces(ctrl, std::move(cb));
        });
    }

    MOCK_METHOD(void, start, (const std::shared_ptr<MctpEndpoint>&),
                (override));
    MOCK_METHOD(void, stop, (), (override));
    MOCK_METHOD(void, recover, (), (override));
    MOCK_METHOD(int, getNID, (), (const override));
    MOCK_METHOD(int, getEID, (), (const override));
    MOCK_METHOD(void, miSubsystemHealthStatusPoll,
                (std::function<void(const std::error_code&,
                                    nvme_mi_nvm_ss_health_status*)>&&),
                (override));
    MOCK_METHOD(void, miScanCtrl,
                (std::function<void(const std::error_code&,
                                    const std::vector<nvme_mi_ctrl_t>&)>),
                (override));
    MOCK_METHOD(bool, flushOperations, (std::function<void()>&&));
    MOCK_METHOD(void, adminIdentify,
                (nvme_mi_ctrl_t ctrl, nvme_identify_cns cns, uint32_t nsid,
                 uint16_t cntid,
                 std::function<void(nvme_ex_ptr, std::span<uint8_t>)>&& cb),
                (override));
    MOCK_METHOD(
        void, adminGetLogPage,
        (nvme_mi_ctrl_t ctrl, nvme_cmd_get_log_lid lid, uint32_t nsid,
         uint8_t lsp, uint16_t lsi,
         std::function<void(const std::error_code&, std::span<uint8_t>)>&& cb),
        (override));
    MOCK_METHOD(
        void, adminFwCommit,
        (nvme_mi_ctrl_t ctrl, nvme_fw_commit_ca action, uint8_t slot, bool bpid,
         std::function<void(const std::error_code&, nvme_status_field)>&& cb),
        (override));
    MOCK_METHOD(void, adminXfer,
                (nvme_mi_ctrl_t ctrl, const nvme_mi_admin_req_hdr& admin_req,
                 std::span<uint8_t> data, unsigned int timeout_ms,
                 std::function<void(const std::error_code& ec,
                                    const nvme_mi_admin_resp_hdr& admin_resp,
                                    std::span<uint8_t> resp_data)>&& cb),
                (override));

    MOCK_METHOD(
        void, adminSecuritySend,
        (nvme_mi_ctrl_t ctrl, uint8_t proto, uint16_t proto_specific,
         std::span<uint8_t> data,
         std::function<void(const std::error_code&, int nvme_status)>&& cb),
        (override));
    MOCK_METHOD(void, adminSecurityReceive,
                (nvme_mi_ctrl_t ctrl, uint8_t proto, uint16_t proto_specific,
                 uint32_t transfer_length,
                 std::function<void(const std::error_code&, int nvme_status,
                                    const std::span<uint8_t> data)>&& cb),
                (override));

    MOCK_METHOD(
        void, adminFwDownload,
        (nvme_mi_ctrl_t ctrl, std::string firmwarefile,
         std::function<void(const std::error_code&, nvme_status_field)>&& cb),
        (override));

    MOCK_METHOD(void, adminNonDataCmd,
                (nvme_mi_ctrl_t ctrl, uint8_t opcode, uint32_t cdw1,
                 uint32_t cdw2, uint32_t cdw3, uint32_t cdw10, uint32_t cdw11,
                 uint32_t cdw12, uint32_t cdw13, uint32_t cdw14, uint32_t cdw15,
                 std::function<void(const std::error_code&, int nvme_status,
                                    uint32_t comption_dw0)>&& cb),
                (override));
    MOCK_METHOD(void, createNamespace,
                (nvme_mi_ctrl_t ctrl, uint64_t size, size_t lba_format,
                 bool metadata_at_end,
                 std::function<void(nvme_ex_ptr ex)>&& submitted_cb,
                 std::function<void(nvme_ex_ptr ex, NVMeNSIdentify newid)>&&
                     finished_cb),
                (override));

    MOCK_METHOD(
        void, adminDeleteNamespace,
        (nvme_mi_ctrl_t ctrl, uint32_t nsid,
         std::function<void(const std::error_code&, int nvme_status)>&& cb),
        (override));

    MOCK_METHOD(
        void, adminAttachDetachNamespace,
        (nvme_mi_ctrl_t ctrl, uint16_t ctrlid, uint32_t nsid, bool attach,
         std::function<void(const std::error_code&, int nvme_status)>&& cb),
        (override));

    MOCK_METHOD(
        void, adminListNamespaces,
        (nvme_mi_ctrl_t ctrl,
         std::function<void(nvme_ex_ptr ex, std::vector<uint32_t> ns)>&& cb),
        (override));

    MOCK_METHOD(void, adminSanitize,
                (nvme_mi_ctrl_t ctrl, enum nvme_sanitize_sanact sanact,
                 uint8_t passes, uint32_t pattern, bool invert_pattern,
                 std::function<void(nvme_ex_ptr ex)>&& cb),
                (override));

    std::shared_ptr<NVMeMiFake> fake;
};

class NVMeTest : public ::testing::Test
{
  protected:
    NVMeTest() :
        object_server(system_bus),
        nvme_intf(NVMeIntf::create<NVMeMiMock>(io, subsys_poll_time / 10)),
        mock(*std::dynamic_pointer_cast<NVMeMiMock>(
                  std::get<std::shared_ptr<NVMeMiIntf>>(
                      nvme_intf.getInferface()))
                  .get()),
        subsys(std::make_shared<NVMeSubsystem>(io, object_server, system_bus,
                                               subsys_path, "NVMe_1",
                                               SensorData{}, nvme_intf))
    {
        subsys->unavailableMaxCount = 1;
        subsys->pollingInterval = subsys_poll_time;
    }

    static void SetUpTestSuite()
    {
        system_bus =
            std::make_shared<sdbusplus::asio::connection>(NVMeTest::io);
        system_bus->request_name("xyz.openbmc_project.NVMeTest");

        // Load plugin shared libraries
        try
        {
            for (const auto& entry :
                 std::filesystem::directory_iterator(xstr(BUILDDIR)))
            {
                void* lib = dlopen(entry.path().c_str(), RTLD_NOW);
                if (lib != nullptr)
                {
                    pluginLibMap.emplace(entry.path().filename().string(), lib);
                }
                else
                {
                    std::cerr << "could not load the plugin: " << dlerror()
                              << std::endl;
                }
            }
        }
        catch (const std::filesystem::filesystem_error& e)
        {
            std::cerr << "failed to open plugin folder: " << e.what()
                      << std::endl;
        }
    }

    void SetUp() override
    {
        subsys->init();
        subsys->start();
    }

    void TearDown() override
    {
        io.restart();
    }

    static constexpr char subsys_path[] =
        "/xyz/openbmc_project/inventory/Test_Chassis/Test_NVMe";

    static boost::asio::io_context io;
    static std::shared_ptr<sdbusplus::asio::connection> system_bus;
    sdbusplus::asio::object_server object_server;

    NVMeIntf nvme_intf;
    NVMeMiMock& mock;
    std::shared_ptr<NVMeSubsystem> subsys;

    const static std::chrono::milliseconds subsys_poll_time;
};

const std::chrono::milliseconds NVMeTest::subsys_poll_time = []() {
    return (RUNNING_ON_VALGRIND) ? std::chrono::milliseconds(1000)
                                 : std::chrono::milliseconds(100);
}();

boost::asio::io_context NVMeTest::io;
std::shared_ptr<sdbusplus::asio::connection> NVMeTest::system_bus;

/**
 * @brief Test start and stop function of NVMeSubsystem
 *
 */
TEST_F(NVMeTest, TestSubsystemStartStop)
{
    using ::testing::AtLeast;
    boost::asio::steady_timer timer(io);

    EXPECT_CALL(mock, miSubsystemHealthStatusPoll).Times(AtLeast(1));
    EXPECT_CALL(mock, adminIdentify).Times(AtLeast(1));
    EXPECT_CALL(mock, miScanCtrl).Times(AtLeast(1));

    // wait for subsystem initialization
    timer.expires_after(subsys_poll_time * 2);
    timer.async_wait([&](boost::system::error_code) {
        system_bus->async_method_call(
            [&, this](boost::system::error_code, const GetSubTreeType& result) {
            // Only PF and the enabled VF should be listed
            EXPECT_EQ(result.size(), 2);
            subsys->stop();

            // wait for storage controller destruction.
            timer.expires_after(subsys_poll_time * 1);
            timer.async_wait([&](boost::system::error_code) {
                system_bus->async_method_call(
                    [&](boost::system::error_code,
                        const GetSubTreeType& result) {
                    // not storage controller should be listed.
                    nlohmann::json j(result);
                    EXPECT_EQ(result.size(), 0)
                        << "The following interfaces remain after STOP: \n"
                        << j.dump(2) << std::endl;
                    // restart the subsystem
                    subsys->start();
                    timer.expires_after(subsys_poll_time * 2);
                    timer.async_wait([&](boost::system::error_code) {
                        system_bus->async_method_call(
                            [&](boost::system::error_code,
                                const GetSubTreeType& result) {
                            EXPECT_EQ(result.size(), 2);

                            subsys->stop();
                            // subsys.reset();

                            // wait for storage controller destruction.
                            timer.expires_after(subsys_poll_time * 1);
                            timer.async_wait([&](boost::system::error_code) {
                                system_bus->async_method_call(
                                    [&](boost::system::error_code,
                                        const GetSubTreeType& result) {
                                    // not storage controller should be listed.
                                    nlohmann::json j(result);
                                    EXPECT_EQ(result.size(), 0)
                                        << "The following interfaces remain after STOP: \n"
                                        << j.dump(2) << std::endl;
                                    io.stop();
                                },
                                    "xyz.openbmc_project.ObjectMapper",
                                    "/xyz/openbmc_project/object_mapper",
                                    "xyz.openbmc_project.ObjectMapper",
                                    "GetSubTree", subsys_path, 0,
                                    std::vector<std::string>{
                                        "xyz.openbmc_project.Inventory."
                                        "Item.StorageController"});
                            });
                        },
                            "xyz.openbmc_project.ObjectMapper",
                            "/xyz/openbmc_project/object_mapper",
                            "xyz.openbmc_project.ObjectMapper", "GetSubTree",
                            subsys_path, 0,
                            std::vector<std::string>{
                                "xyz.openbmc_project.Inventory.Item.StorageController"});
                    });
                },
                    "xyz.openbmc_project.ObjectMapper",
                    "/xyz/openbmc_project/object_mapper",
                    "xyz.openbmc_project.ObjectMapper", "GetSubTree",
                    subsys_path, 0,
                    std::vector<std::string>{"xyz.openbmc_project.Inventory."
                                             "Item.StorageController"});
            });
        }, "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetSubTree", subsys_path, 0,
            std::vector<std::string>{
                "xyz.openbmc_project.Inventory.Item.StorageController"});
    });
    io.run();
}

/**
 * @brief Test NVMeMi return DriveFunctional(NSHDS.NSS.DF) = 0
 *
 */
TEST_F(NVMeTest, TestDriveFunctional)
{
    using ::testing::AtLeast;
    boost::asio::steady_timer timer(io);

    EXPECT_CALL(mock, miSubsystemHealthStatusPoll).Times(AtLeast(1));
    EXPECT_CALL(mock, adminIdentify).Times(AtLeast(1));
    EXPECT_CALL(mock, miScanCtrl).Times(AtLeast(1));

    // wait for subsystem initialization
    timer.expires_after(subsys_poll_time * 2);
    timer.async_wait([&](boost::system::error_code) {
        system_bus->async_method_call(
            [&](boost::system::error_code, const GetSubTreeType& result) {
            // Only PF and the enabled VF should be listed
            EXPECT_EQ(result.size(), 2);

            // mimik communication error of NVMeMI request
            ON_CALL(mock, miSubsystemHealthStatusPoll)
                .WillByDefault(
                    [&](std::function<void(const std::error_code&,
                                           nvme_mi_nvm_ss_health_status*)>&&
                            cb) {
                std::cerr << "mock device not functional health poll"
                          << std::endl;
                // return status.nss.df = 0
                return io.post([cb = std::move(cb)]() {
                    nvme_mi_nvm_ss_health_status status;
                    status.nss = 0;
                    cb({}, &status);
                });
            });

            // wait for storage controller destruction.
            timer.expires_after(subsys_poll_time * 2);
            timer.async_wait([&](boost::system::error_code) {
                system_bus->async_method_call(
                    [&](boost::system::error_code,
                        const GetSubTreeType& result) {
                    // no storage controller should be listed.
                    nlohmann::json j(result);
                    EXPECT_EQ(result.size(), 0)
                        << "The following interfaces remain after unfunctional: \n"
                        << j.dump(2) << std::endl;

                    // restart sending DF = 1
                    ON_CALL(mock, miSubsystemHealthStatusPoll)
                        .WillByDefault(
                            [&](std::function<void(
                                    const std::error_code&,
                                    nvme_mi_nvm_ss_health_status*)>&& cb) {
                        return mock.fake->miSubsystemHealthStatusPoll(
                            std::move(cb));
                    });
                    timer.expires_after(subsys_poll_time * 2);
                    timer.async_wait([&](boost::system::error_code) {
                        system_bus->async_method_call(
                            [&](boost::system::error_code,
                                const GetSubTreeType& result) {
                            // storage controller should be restored.
                            EXPECT_EQ(result.size(), 2);

                            subsys->stop();
                            // subsys.reset();

                            // wait for storage controller destruction.
                            timer.expires_after(subsys_poll_time * 1);
                            timer.async_wait([&](boost::system::error_code) {
                                system_bus->async_method_call(
                                    [&](boost::system::error_code,
                                        const GetSubTreeType& result) {
                                    // not storage controller should be listed.
                                    nlohmann::json j(result);
                                    EXPECT_EQ(result.size(), 0)
                                        << "The following interfaces remain after STOP: \n"
                                        << j.dump(2) << std::endl;
                                    io.stop();
                                },
                                    "xyz.openbmc_project.ObjectMapper",
                                    "/xyz/openbmc_project/object_mapper",
                                    "xyz.openbmc_project.ObjectMapper",
                                    "GetSubTree", subsys_path, 0,
                                    std::vector<std::string>{
                                        "xyz.openbmc_project.Inventory."
                                        "Item.StorageController"});
                            });
                        },
                            "xyz.openbmc_project.ObjectMapper",
                            "/xyz/openbmc_project/object_mapper",
                            "xyz.openbmc_project.ObjectMapper", "GetSubTree",
                            subsys_path, 0,
                            std::vector<std::string>{
                                "xyz.openbmc_project.Inventory."
                                "Item.StorageController"});
                    });
                },
                    "xyz.openbmc_project.ObjectMapper",
                    "/xyz/openbmc_project/object_mapper",
                    "xyz.openbmc_project.ObjectMapper", "GetSubTree",
                    subsys_path, 0,
                    std::vector<std::string>{"xyz.openbmc_project.Inventory."
                                             "Item.StorageController"});
            });
        }, "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetSubTree", subsys_path, 0,
            std::vector<std::string>{
                "xyz.openbmc_project.Inventory.Item.StorageController"});
    });
    io.run();
}

/**
 * @brief Test NVMeMi returns Drive is absent (ec = no_such_device)
 *
 */
TEST_F(NVMeTest, TestDriveAbsent)
{
    using ::testing::AtLeast;
    boost::asio::steady_timer timer(io);

    EXPECT_CALL(mock, miSubsystemHealthStatusPoll).Times(AtLeast(1));
    EXPECT_CALL(mock, adminIdentify).Times(AtLeast(1));
    EXPECT_CALL(mock, miScanCtrl).Times(AtLeast(1));

    // wait for subsystem initialization
    timer.expires_after(subsys_poll_time * 2);
    timer.async_wait([&](boost::system::error_code) {
        system_bus->async_method_call(
            [&](boost::system::error_code, const GetSubTreeType& result) {
            // Only PF and the enabled VF should be listed
            EXPECT_EQ(result.size(), 2);

            // mimik communication error of NVMeMI request
            ON_CALL(mock, miSubsystemHealthStatusPoll)
                .WillByDefault(
                    [&](std::function<void(const std::error_code&,
                                           nvme_mi_nvm_ss_health_status*)>&&
                            cb) {
                std::cerr << "mock device absent health poll" << std::endl;
                // return no_such_device
                return io.post([cb = std::move(cb)]() {
                    cb(std::make_error_code(std::errc::no_such_device),
                       nullptr);
                });
            });

            // wait for storage controller destruction.
            timer.expires_after(subsys_poll_time * 2);
            timer.async_wait([&](boost::system::error_code) {
                system_bus->async_method_call(
                    [&](boost::system::error_code,
                        const GetSubTreeType& result) {
                    // no storage controller should be listed.
                    nlohmann::json j(result);
                    EXPECT_EQ(result.size(), 0)
                        << "The following interfaces remain after absent: \n"
                        << j.dump(2) << std::endl;

                    // restart sending normal polling result
                    ON_CALL(mock, miSubsystemHealthStatusPoll)
                        .WillByDefault(
                            [&](std::function<void(
                                    const std::error_code&,
                                    nvme_mi_nvm_ss_health_status*)>&& cb) {
                        return mock.fake->miSubsystemHealthStatusPoll(
                            std::move(cb));
                    });
                    timer.expires_after(subsys_poll_time * 2);
                    timer.async_wait([&](boost::system::error_code) {
                        system_bus->async_method_call(
                            [&](boost::system::error_code,
                                const GetSubTreeType& result) {
                            // storage controller should be restored.
                            EXPECT_EQ(result.size(), 2);

                            subsys->stop();

                            // wait for storage controller destruction.
                            timer.expires_after(subsys_poll_time * 1);
                            timer.async_wait([&](boost::system::error_code) {
                                system_bus->async_method_call(
                                    [&](boost::system::error_code,
                                        const GetSubTreeType& result) {
                                    // not storage controller should be listed.
                                    nlohmann::json j(result);
                                    EXPECT_EQ(result.size(), 0)
                                        << "The following interfaces remain after STOP: \n"
                                        << j.dump(2) << std::endl;
                                    io.stop();
                                },
                                    "xyz.openbmc_project.ObjectMapper",
                                    "/xyz/openbmc_project/object_mapper",
                                    "xyz.openbmc_project.ObjectMapper",
                                    "GetSubTree", subsys_path, 0,
                                    std::vector<std::string>{
                                        "xyz.openbmc_project.Inventory."
                                        "Item.StorageController"});
                            });
                        },
                            "xyz.openbmc_project.ObjectMapper",
                            "/xyz/openbmc_project/object_mapper",
                            "xyz.openbmc_project.ObjectMapper", "GetSubTree",
                            subsys_path, 0,
                            std::vector<std::string>{
                                "xyz.openbmc_project.Inventory."
                                "Item.StorageController"});
                    });
                },
                    "xyz.openbmc_project.ObjectMapper",
                    "/xyz/openbmc_project/object_mapper",
                    "xyz.openbmc_project.ObjectMapper", "GetSubTree",
                    subsys_path, 0,
                    std::vector<std::string>{"xyz.openbmc_project.Inventory."
                                             "Item.StorageController"});
            });
        }, "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetSubTree", subsys_path, 0,
            std::vector<std::string>{
                "xyz.openbmc_project.Inventory.Item.StorageController"});
    });
    io.run();
}

/**
 * @brief Inject error during subsystem initialization process. The subsystem is
 * expected to recover after the error
 */
TEST_F(NVMeTest, InitErrorInjection)
{
    using ::testing::_;
    using ::testing::AnyNumber;
    using ::testing::AtLeast;
    using ::testing::Eq;
    boost::asio::steady_timer timer(io);

    EXPECT_CALL(mock, miSubsystemHealthStatusPoll).Times(AtLeast(1));
    EXPECT_CALL(mock, miScanCtrl)
        .WillOnce([](std::function<void(const std::error_code&,
                                        const std::vector<nvme_mi_ctrl_t>&)>
                         cb) {
        cb(std::make_error_code(std::errc::no_such_device), {});
    }).WillRepeatedly([&](auto&& cb) {
        return mock.fake->miScanCtrl(std::forward<decltype(cb)>(cb));
    });

    EXPECT_CALL(mock, adminIdentify).Times(::testing::AnyNumber());

    // Failed on the first query on id_sec_cntrl_list
    EXPECT_CALL(
        mock,
        adminIdentify(
            _, Eq(nvme_identify_cns::NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST), _,
            _, _))
        .WillOnce([]<class... Args>(Args... args) -> void {
        auto&& cb = std::get<sizeof...(Args) - 1>(std::tie(args...));
        return cb(
            makeLibNVMeError(0, NVME_MI_RESP_INVALID_PARAM, "adminIdentify"),
            {});
    }).WillRepeatedly([&]<class... Args>(Args&&... args) {
        return mock.fake->adminIdentify(std::forward<Args>(args)...);
    });

    // failed on first id_allocated_ns
    EXPECT_CALL(
        mock,
        adminIdentify(_, Eq(nvme_identify_cns::NVME_IDENTIFY_CNS_ALLOCATED_NS),
                      _, _, _))
        .Times(AnyNumber()) // allow to run at 0 times based on given NS number
        .WillOnce([]<class... Args>(Args... args) -> void {
        auto&& cb = std::get<sizeof...(Args) - 1>(std::tie(args...));
        return cb(
            makeLibNVMeError(0, NVME_MI_RESP_INVALID_PARAM, "adminIdentify"),
            {});
    }).WillRepeatedly([&]<class... Args>(Args&&... args) {
        return mock.fake->adminIdentify(std::forward<Args>(args)...);
    });

    // failed on first id_ns_cntrl
    EXPECT_CALL(
        mock,
        adminIdentify(_, Eq(nvme_identify_cns::NVME_IDENTIFY_CNS_NS_CTRL_LIST),
                      _, _, _))
        .Times(AnyNumber()) // allow to run at 0 times based on given NS number
        .WillOnce([]<class... Args>(Args... args) -> void {
        auto&& cb = std::get<sizeof...(Args) - 1>(std::tie(args...));
        return cb(
            makeLibNVMeError(0, NVME_MI_RESP_INVALID_PARAM, "adminIdentify"),
            {});
    }).WillRepeatedly([&]<class... Args>(Args&&... args) {
        return mock.fake->adminIdentify(std::forward<Args>(args)...);
    });

    // failed on first id_cntrl
    EXPECT_CALL(mock,
                adminIdentify(_, Eq(nvme_identify_cns::NVME_IDENTIFY_CNS_CTRL),
                              _, _, _))
        .WillOnce([]<class... Args>(Args... args) -> void {
        auto&& cb = std::get<sizeof...(Args) - 1>(std::tie(args...));
        return cb(
            makeLibNVMeError(0, NVME_MI_RESP_INVALID_PARAM, "adminIdentify"),
            {});
    }).WillRepeatedly([&]<class... Args>(Args&&... args) {
        return mock.fake->adminIdentify(std::forward<Args>(args)...);
    });

    // failed on first id_ns
    EXPECT_CALL(
        mock,
        adminIdentify(_, Eq(nvme_identify_cns::NVME_IDENTIFY_CNS_NS), _, _, _))
        .Times(AnyNumber()) // allow to run at 0 times based on given NS number
        .WillOnce([]<class... Args>(Args... args) -> void {
        auto&& cb = std::get<sizeof...(Args) - 1>(std::tie(args...));
        return cb(
            makeLibNVMeError(0, NVME_MI_RESP_INVALID_PARAM, "adminIdentify"),
            {});
    }).WillRepeatedly([&]<class... Args>(Args&&... args) {
        return mock.fake->adminIdentify(std::forward<Args>(args)...);
    });

    // Failed on list namespace
    EXPECT_CALL(mock, adminListNamespaces)
        .WillOnce([]<class... Args>(Args... args) -> void {
        auto&& cb = std::get<sizeof...(Args) - 1>(std::tie(args...));
        return cb(
            makeLibNVMeError(0, NVME_MI_RESP_INVALID_PARAM, "adminIdentify"),
            {});
    }).WillRepeatedly([&]<class... Args>(Args&&... args) {
        return mock.fake->adminListNamespaces(std::forward<Args>(args)...);
    });

    // wait for subsystem initialization, each failure will introduce 1 second
    // delay for retry
    timer.expires_after(subsys_poll_time * (2 + 10));
    timer.async_wait([&](boost::system::error_code) {
        system_bus->async_method_call(
            [&, this](boost::system::error_code, const GetSubTreeType& result) {
            // Only PF and the enabled VF should be listed
            EXPECT_EQ(result.size(), 2);
            subsys->stop();

            // wait for storage controller destruction.
            timer.expires_after(subsys_poll_time * 1);
            timer.async_wait([&](boost::system::error_code) {
                system_bus->async_method_call(
                    [&](boost::system::error_code,
                        const GetSubTreeType& result) {
                    // not storage controller should be listed.
                    nlohmann::json j(result);
                    EXPECT_EQ(result.size(), 0)
                        << "The following interfaces remain after STOP: \n"
                        << j.dump(2) << std::endl;
                    io.stop();
                },
                    "xyz.openbmc_project.ObjectMapper",
                    "/xyz/openbmc_project/object_mapper",
                    "xyz.openbmc_project.ObjectMapper", "GetSubTree",
                    subsys_path, 0,
                    std::vector<std::string>{"xyz.openbmc_project.Inventory."
                                             "Item.StorageController"});
            });
        }, "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetSubTree", subsys_path, 0,
            std::vector<std::string>{
                "xyz.openbmc_project.Inventory.Item.StorageController"});
    });
    io.run();
}
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
