#pragma once

#include <sdbusplus/exception.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <iostream>
#include <memory>
#include <system_error>

namespace CommonErr = sdbusplus::xyz::openbmc_project::Common::Error;

class NVMeError;
using nvme_ex_ptr = std::shared_ptr<NVMeError>;

/*
 * Holds various types of errors that could be handled
 * by nvmesensor. These include errors from libnvme, argument checking,
 * and other unexpected failures.
 * Instances are kept in a shared_ptr so that
 * they can be passed across the asio async boundary when
 * needed.
 *
 * Specific error subclasses (from phosphor-dbus-interfaces)
 * are later thrown so that sdbusplus bindings
 * will catch the correct exception.
 *
 * TODO: the descriptive error text (as returned from print()) is currently not
 * passed back over dbus. Eventually this should be passed so it can
 * be included in bmcweb redfish responses.
 */
class NVMeError
{
  public:
    // Returns a new NVMeError shared_ptr
    static nvme_ex_ptr makeInternalError(std::string_view desc);
    static nvme_ex_ptr makeInternalError(const std::error_code& err);
    static nvme_ex_ptr makeInvalidArgument(std::string_view desc);

    // Returns nullptr if no error is set, or a new NVMeError pointer
    static nvme_ex_ptr checkLibNVMe(const std::error_code& err,
        int nvme_status);
    static nvme_ex_ptr checkLibNVMe(int nvme_errno, int nvme_status);

    std::string description() const;
    std::string name() const;

    /* Throws the relevant exception, which will be a subclass
     * of sdbusplus::exception_t
     */
    [[ noreturn ]] void throw_specific(bool print = false) const;
  private:
    NVMeError(std::string_view internalError,
      std::string_view invalidArgument,
      int nvme_status);

    [[ noreturn ]] static void throwNVMeStatus(int nvme_status);
    [[ noreturn ]] static void throwLibNVMe(int val);
    [[ noreturn ]] static void throwLibNVMeMI(int val);

    static std::string getNVMeStatusMessage(int nvme_status);

    /* Only one of the following should be "set".
     * TODO: once the structure has settled these could become
     * subclasses or add an ErrorType enum.
     */

    std::string internalError;

    std::string invalidArgument;

    /* A status code returned from libnvme.
     * Will always be a positive integer if set.
     * A value of 0 means "unset" - not a libnvme error (negative
     * status codes and errno are recorded as internalError)
     */
    int libnvme_error;
};

/* Throws an appropriate error type for the given status from libnvme,
 * or returns normally if nvme_status == 0 */
void checkLibNVMeError(const std::error_code& err, int nvme_status);

// std::ostream& operator<<(std::ostream& o, nvme_ex_ptr ex);
