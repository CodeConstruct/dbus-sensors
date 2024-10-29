#include "NVMeError.hpp"

#include <libnvme-mi.h>

#include <xyz/openbmc_project/Common/Device/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

NVMeSdBusPlusError::NVMeSdBusPlusError(std::string_view desc) : desc(desc)
{
    init();
}

NVMeSdBusPlusError::NVMeSdBusPlusError(
// NOLINTNEXTLINE(bugprone-throw-keyword-missing)
    std::shared_ptr<sdbusplus::exception_t> &&specific) : specific(specific)
{
    init();
}

NVMeSdBusPlusError::NVMeSdBusPlusError(
    std::string_view desc, std::shared_ptr<sdbusplus::exception_t> &&specific) :
// NOLINTNEXTLINE(bugprone-throw-keyword-missing)
    desc(desc), specific(specific)
{
    init();
}

void NVMeSdBusPlusError::init()
{
    whatMsg = std::string(name()) + ": " + description();
}

const char* NVMeSdBusPlusError::name() const noexcept
{
    if (specific)
    {
        return specific->name();
    }
    return CommonErr::InternalFailure().name();
}

const char* NVMeSdBusPlusError::description() const noexcept
{
    if (!desc.empty())
    {
        return desc.c_str();
    }
    if (specific)
    {
        return specific->description();
    }
    return "nvmesensor internal error";
}

const char* NVMeSdBusPlusError::what() const noexcept
{
    return whatMsg.c_str();
}

int NVMeSdBusPlusError::get_errno() const noexcept
{
    if (specific)
    {
        return specific->get_errno();
    }
    // arbitrary, sdbusplus method return ignores this errno
    return EIO;
}

void NVMeSdBusPlusError::print(std::ostream& o) const
{
    o << description();
}

/* Converts a subset of known status codes to dbus enums */
static void translateLibNVMe(int val, std::string& desc,
                             std::shared_ptr<sdbusplus::exception_t>& specific)
{
    uint16_t sc = nvme_status_code(val);
    uint16_t sct = nvme_status_code_type(val);

    switch (sct)
    {
        case NVME_SCT_GENERIC:
            switch (sc)
            {
                case NVME_SC_INVALID_FIELD:
                    specific = std::make_shared<CommonErr::InvalidArgument>();
                    break;

                case NVME_SC_CAP_EXCEEDED:
                    specific = std::make_shared<CommonErr::TooManyResources>();
                    break;

                case NVME_SC_SANITIZE_IN_PROGRESS:
                    specific = std::make_shared<CommonErr::Unavailable>();
                    break;

                default:
                    specific =
                        std::make_shared<CommonErr::DeviceOperationFailed>();
            }
            break;
        case NVME_SCT_CMD_SPECIFIC:
            switch (sc)
            {
                case NVME_SC_INVALID_FORMAT:
                    specific = std::make_shared<CommonErr::InvalidArgument>();
                    break;

                case NVME_SC_INSUFFICIENT_CAP:
                case NVME_SC_NS_INSUFFICIENT_CAP:
                case NVME_SC_NS_ID_UNAVAILABLE:
                case NVME_SC_NS_ATTACHMENT_LIMIT_EXCEEDED:
                    specific = std::make_shared<CommonErr::TooManyResources>();
                    break;

                case NVME_SC_FW_NEEDS_SUBSYS_RESET:
                case NVME_SC_FW_NEEDS_RESET:
                    specific = std::make_shared<CommonErr::Unavailable>();
                    break;

                default:
                    specific =
                        std::make_shared<CommonErr::DeviceOperationFailed>();
            }
            break;
        default:
            specific = std::make_shared<CommonErr::DeviceOperationFailed>();
    }

    // always return the description from libnvme
    std::ostringstream s;
    s << "NVMe: " << nvme_status_to_string(val, false) << " (SCT " << sct
      << " SC 0x" << std::hex << sc << ")";
    desc = s.str();
}

static void
    translateLibNVMeMI(int val, std::string& desc,
                       std::shared_ptr<sdbusplus::exception_t>& specific)
{
    switch (val)
    {
        case NVME_MI_RESP_INVALID_PARAM:
            specific = std::make_shared<CommonErr::InvalidArgument>();
            break;

        case NVME_MI_RESP_SANITIZE_IN_PROGRESS:
            specific = std::make_shared<CommonErr::Unavailable>();
            break;

        // INVALID_CMD_SIZE is returned by some drives
        case NVME_MI_RESP_INVALID_OPCODE:
        case NVME_MI_RESP_INVALID_CMD_SIZE:
            specific = std::make_shared<CommonErr::UnsupportedRequest>();
            break;

        default:
            specific = std::make_shared<CommonErr::DeviceOperationFailed>();
    }

    // always return the description from libnvme
    std::ostringstream s;
    s << "NVMe MI: " << nvme_mi_status_to_string(val) << " (MI status 0x"
      << std::hex << val << ")";
    desc = s.str();
}

nvme_ex_ptr makeLibNVMeError(const std::error_code& err, int nvmeStatus,
                             const char* methodName)
{
    // TODO: possibly remove method_name argument
    (void)methodName;

    if (nvmeStatus < 0)
    {
        auto desc = std::string("libnvme error: ") + err.message();
        std::cerr << methodName << ":" << desc << std::endl;
        return std::make_shared<NVMeSdBusPlusError>(desc);
    }
    if (nvmeStatus > 0)
    {
        int val = nvme_status_get_value(nvmeStatus);
        int ty = nvme_status_get_type(nvmeStatus);
        std::string desc;
        std::shared_ptr<sdbusplus::exception_t> specific;

        switch (ty)
        {
            case NVME_STATUS_TYPE_NVME:
                translateLibNVMe(val, desc, specific);
                break;
            case NVME_STATUS_TYPE_MI:
                translateLibNVMeMI(val, desc, specific);
                break;
            default:
                std::cerr << "Unknown libnvme error status " << nvmeStatus
                          << std::endl;
                desc = "Unknown libnvme error";
        }
        std::cerr << methodName << ":" << desc << std::endl;
        return std::make_shared<NVMeSdBusPlusError>(desc, std::move(specific));
    }
    // No Error
    return nullptr;
}

nvme_ex_ptr makeLibNVMeError(int nvmeErrno, int nvmeStatus,
                             const char* methodName)
{
    auto err = std::make_error_code(static_cast<std::errc>(nvmeErrno));
    return makeLibNVMeError(err, nvmeStatus, methodName);
}

nvme_ex_ptr makeLibNVMeError(std::string_view msg)
{
    return std::make_shared<NVMeSdBusPlusError>(msg);
}

nvme_ex_ptr makeLibNVMeError(std::string_view desc,
                             std::shared_ptr<sdbusplus::exception_t> specific)
{
    return std::make_shared<NVMeSdBusPlusError>(desc, std::move(specific));
}

/* Throws an appropriate error type for the given status from libnvme,
 * or returns normally if nvme_status == 0 */
void checkLibNVMeError(const std::error_code& err, int nvmeStatus,
                       const char* methodName)
{
    auto e = makeLibNVMeError(err, nvmeStatus, methodName);
    if (e)
    {
        throw std::move(*e);
    }
}

std::ostream& operator<<(std::ostream& o, const nvme_ex_ptr &ex)
{
    if (ex)
    {
        ex->print(o);
    }
    else
    {
        o << "(null nvme_ex_ptr)";
    }
    return o;
}
