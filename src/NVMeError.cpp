#include "NVMeError.hpp"

#include <libnvme-mi.h>

#include <sdbusplus/exception.hpp>
#include <xyz/openbmc_project/Common/Device/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

nvme_ex_ptr NVMeError::makeInternalError(std::string_view desc)
{
    std::ostringstream s;
    s << "internal error: " << desc;
    return std::shared_ptr<NVMeError>(new NVMeError(s.str(), "", 0));
}

nvme_ex_ptr NVMeError::makeInternalError(const std::error_code& err)
{
    return makeInternalError(err.message());
}

nvme_ex_ptr NVMeError::makeInvalidArgument(std::string_view desc)
{
    std::ostringstream s;
    s << "invalid argument: " << desc;
    return std::shared_ptr<NVMeError>(new NVMeError("", s.str(), 0));
}

nvme_ex_ptr NVMeError::checkLibNVMe(const std::error_code& err,
        int nvme_status)
{
    if (nvme_status < 0) {
        return makeInternalError(std::string("libnvme error: ") + err.message());
    } else if (nvme_status > 0) {
        return std::shared_ptr<NVMeError>(new NVMeError("", "", nvme_status));
    }
    return nullptr;
}

nvme_ex_ptr NVMeError::checkLibNVMe(int nvme_errno, int nvme_status)
{
    auto err = std::make_error_code(static_cast<std::errc>(nvme_errno));
    return checkLibNVMe(err, nvme_status);
}

NVMeError::NVMeError(std::string_view internalError,
    std::string_view invalidArgument,
    int nvme_status) :
    internalError(internalError),
    invalidArgument(invalidArgument),
    libnvme_error(nvme_status)
{
}

std::string NVMeError::description() const
{
    if (!internalError.empty()) {
        return internalError;
    }
    if (!invalidArgument.empty()) {
        return invalidArgument;
    }
    if (libnvme_error) {
        return std::string("libnvme error ")
            + getNVMeStatusMessage(libnvme_error);
    }
    // unreachable
    return "";
}

std::string NVMeError::name() const
{
    std::string n;
    try {
        throw_specific(false);
    } catch (sdbusplus::exception_t & e) {
        n = e.name();
    }
    return n;
}

void NVMeError::throw_specific(bool print) const
{
    try 
    {
        if (!invalidArgument.empty()) {
            throw CommonErr::InvalidArgument();
        }

        if (libnvme_error) {
            throwNVMeStatus(libnvme_error);
        }

        if (internalError.empty()) {
            // None are set! InternalFailure suits anyway
            std::cerr << "incomplete NVMeError\n";
        }

        throw CommonErr::InternalFailure();
    } catch (sdbusplus::exception_t &e) {
        // catch to get the name
        if (print) {
            std::cerr << "throwing NVMeError exception "
                << e.name() << ". "
                << description() << "\n";
        }
        throw;
    }

}

std::string NVMeError::getNVMeStatusMessage(int nvme_status)
{
    if (nvme_status <= 0)
    {
        return "Unexpected non-error";
    }


    int val = nvme_status_get_value(nvme_status);
    int ty = nvme_status_get_type(nvme_status);

    std::ostringstream s;
    switch (ty)
    {
        case NVME_STATUS_TYPE_NVME:
            {
                uint16_t sc = nvme_status_code(val);
                uint16_t sct = nvme_status_code_type(val);
                s << "NVMe: " << nvme_status_to_string(val, false) << " (SCT " << sct
                    << " SC 0x" << std::hex << sc << ")";
            }
            break;
        case NVME_STATUS_TYPE_MI:
            s << "NVMe MI: " << nvme_mi_status_to_string(val) << " (MI status 0x"
              << std::hex << val << ")";
                return s.str();
            break;
        default:
            s << "Unknown libnvme error status " << nvme_status;
    }
    return s.str();
}

void NVMeError::throwNVMeStatus(int nvme_status)
{
    if (nvme_status > 0)
    {

        int val = nvme_status_get_value(nvme_status);
        int ty = nvme_status_get_type(nvme_status);

        switch (ty)
        {
            case NVME_STATUS_TYPE_NVME:
                throwLibNVMe(val);
                break;
            case NVME_STATUS_TYPE_MI:
                throwLibNVMeMI(val);
                break;
        }
    }

    // fallback
    std::cerr << "throwNVMeStatus called for invalid nvme_status "
        << nvme_status << "\n";
    throw CommonErr::InternalFailure();
}

/* Converts a subset of known status codes to dbus enums */
void NVMeError::throwLibNVMe(int val)
{
    uint16_t sc = nvme_status_code(val);
    uint16_t sct = nvme_status_code_type(val);

    switch (sct)
    {
        case NVME_SCT_GENERIC:
            switch (sc)
            {
                case NVME_SC_INVALID_FIELD:
                    throw CommonErr::InvalidArgument();
                    break;

                case NVME_SC_CAP_EXCEEDED:
                    throw CommonErr::TooManyResources();
                    break;

                case NVME_SC_SANITIZE_IN_PROGRESS:
                    throw CommonErr::Unavailable();
                    break;
            }
            break;
        case NVME_SCT_CMD_SPECIFIC:
            switch (sc)
            {
                case NVME_SC_INVALID_FORMAT:
                    throw CommonErr::InvalidArgument();
                    break;

                case NVME_SC_INSUFFICIENT_CAP:
                case NVME_SC_NS_INSUFFICIENT_CAP:
                case NVME_SC_NS_ID_UNAVAILABLE:
                case NVME_SC_NS_ATTACHMENT_LIMIT_EXCEEDED:
                    throw CommonErr::TooManyResources();
                    break;

                case NVME_SC_FW_NEEDS_SUBSYS_RESET:
                case NVME_SC_FW_NEEDS_RESET:
                    throw CommonErr::Unavailable();
                    break;
            }
            break;
    }

    // fallback
    throw CommonErr::DeviceOperationFailed();

}

void NVMeError::throwLibNVMeMI(int val)
{
    switch (val)
    {
        case NVME_MI_RESP_INVALID_PARAM:
            throw CommonErr::InvalidArgument();
            break;

        case NVME_MI_RESP_SANITIZE_IN_PROGRESS:
            throw CommonErr::Unavailable();
            break;

        // INVALID_CMD_SIZE is returned by some drives
        case NVME_MI_RESP_INVALID_OPCODE:
        case NVME_MI_RESP_INVALID_CMD_SIZE:
            throw CommonErr::UnsupportedRequest();
            break;

        default:
            throw CommonErr::DeviceOperationFailed();
    }
}

/* Throws an appropriate error type for the given status from libnvme,
 * or returns normally if nvme_status == 0 */
void checkLibNVMeError(const std::error_code& err, int nvme_status)
{
    auto e = NVMeError::checkLibNVMe(err, nvme_status);
    if (e)
    {
        e->throw_specific();
    }
}

// std::ostream& operator<<(std::ostream& o, nvme_ex_ptr ex)
// {
//     if (ex)
//     {
//         ex->print(o);
//     }
//     else
//     {
//         o << "(null nvme_ex_ptr)";
//     }
//     return o;
// }
