#pragma once

#include <sdbusplus/exception.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <iostream>
#include <memory>
#include <system_error>

namespace CommonErr = sdbusplus::xyz::openbmc_project::Common::Error;

class NVMeSdBusPlusError final : public sdbusplus::exception_t
{
  public:
    // In general makeLibNVMeError() should be used rather than raw
    // constructors.
    explicit NVMeSdBusPlusError(std::string_view desc);
    explicit NVMeSdBusPlusError(std::shared_ptr<sdbusplus::exception_t> &&specific);
    NVMeSdBusPlusError(std::string_view desc,
                       std::shared_ptr<sdbusplus::exception_t> &&specific);

    const char* what() const noexcept override;
    const char* name() const noexcept override;
    const char* description() const noexcept override;
    int get_errno() const noexcept override;
    void print(std::ostream& o) const;

  private:
    void init();
    const std::string desc;
    std::shared_ptr<sdbusplus::exception_t> specific;
    std::string whatMsg;
};

using nvme_ex_ptr = std::shared_ptr<NVMeSdBusPlusError>;

/* Translates an error from libnvme */
nvme_ex_ptr makeLibNVMeError(const std::error_code& err, int nvmeStatus,
                             const char* methodName);
nvme_ex_ptr makeLibNVMeError(int nvmeErrno, int nvmeStatus,
                             const char* methodName);

/* Creates an internal error */
nvme_ex_ptr makeLibNVMeError(std::string_view msg);
/* Creates an error based on a known exception type */
nvme_ex_ptr makeLibNVMeError(std::string_view desc,
                             std::shared_ptr<sdbusplus::exception_t> specific);

/* Throws an appropriate error type for the given status from libnvme,
 * or returns normally if nvme_status == 0 */
void checkLibNVMeError(const std::error_code& err, int nvmeStatus,
                       const char* methodName);

std::ostream& operator<<(std::ostream& o, const nvme_ex_ptr &ex);
