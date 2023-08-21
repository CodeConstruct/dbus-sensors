#pragma once
#include "NVMeSensor.hpp"

#include <boost/algorithm/string/join.hpp>
#include <boost/asio.hpp>

#include <filesystem>
#include <iostream>
#include <optional>
#include <system_error>

inline std::filesystem::path deriveRootBusPath(int busNumber)
{
    return "/sys/bus/i2c/devices/i2c-" + std::to_string(busNumber) +
           "/mux_device";
}

inline std::optional<int> deriveRootBus(std::optional<int> busNumber)
{
    if (!busNumber)
    {
        return std::nullopt;
    }

    std::filesystem::path muxPath = deriveRootBusPath(*busNumber);

    if (!std::filesystem::is_symlink(muxPath))
    {
        return *busNumber;
    }

    std::string rootName = std::filesystem::read_symlink(muxPath).filename();
    size_t dash = rootName.find('-');
    if (dash == std::string::npos)
    {
        std::cerr << "Error finding root bus for " << rootName << "\n";
        return std::nullopt;
    }

    return std::stoi(rootName.substr(0, dash));
}

inline std::optional<std::string>
    extractOneFromTail(std::string::const_reverse_iterator& rbegin,
                       const std::string::const_reverse_iterator& rend)
{
    std::string name;
    auto curr = rbegin;
    // remove the ending '/'s
    while (rbegin != rend && *rbegin == '/')
    {
        rbegin++;
    }
    if (rbegin == rend)
    {
        return std::nullopt;
    }
    curr = rbegin++;

    // extract word
    while (rbegin != rend && *rbegin != '/')
    {
        rbegin++;
    }
    if (rbegin == rend)
    {
        return std::nullopt;
    }
    name.append(rbegin.base(), curr.base());
    return {name};
}

// a path of
// "/xyz/openbmc_project/inventory/system/board/{prod}/{nvme}/{substruct}..."
// will generates a sensor name {prod}_{nvme}_{substruct}...
inline std::optional<std::string>
    createSensorNameFromPath(const std::string& path)
{
    if (path.empty())
    {
        return std::nullopt;
    }
    auto rbegin = path.crbegin();
    std::vector<std::string> names;
    do
    {
        auto name = extractOneFromTail(rbegin, path.crend());
        if (!name)
        {
            return std::nullopt;
        }
        else if (*name == "board")
        {
            break;
        }

        if (!names.empty() && names.back().starts_with(*name))
        {
            // Skip potential duplicate prefix
            continue;
        }
        names.push_back(*name);
    } while (rbegin != path.rend());

    std::reverse(names.begin(), names.end());
    auto sensorName = boost::algorithm::join(names, "_");
    return sensorName;
}

// Function to update NVMe temp sensor

// Function type for fetching ctemp which encaplucated in a structure of T.
// The fetcher function take a callback as input to process the result.
template <class T>
using ctemp_fetch_t =
    std::function<void(std::function<void(const std::error_code&, T)>&&)>;

// Function type for processing ctemp out the structure of type T.
// The process function will update the properties based on input data.
template <class T>
using ctemp_process_t =
    std::function<void(const std::error_code& error, T data)>;

template <class T>
void pollCtemp(
    std::weak_ptr<boost::asio::steady_timer> timer,
    std::chrono::duration<double, std::milli> delay,
    const std::function<void(std::function<void(const std::error_code&, T)>&&)>&
        dataFetcher,
    const std::function<void(const std::error_code& error, T data)>&
        dataProcessor);

namespace detail
{

template <class T>
void updateCtemp(std::weak_ptr<boost::asio::steady_timer> timer,
                 std::chrono::duration<double, std::milli> delay,
                 ctemp_process_t<T> dataProcessor, ctemp_fetch_t<T> dataFetcher,
                 const std::error_code& error, T data)
{
    if (timer.expired())
    {
        dataProcessor(std::make_error_code(std::errc::operation_canceled),
                      data);
        return;
    }

    dataProcessor(error, data);
    ::pollCtemp(std::move(timer), std::move(delay), dataFetcher, dataProcessor);
}

template <class T>
void pollCtemp(std::weak_ptr<boost::asio::steady_timer> timer,
               std::chrono::duration<double, std::milli> delay,
               ctemp_fetch_t<T> dataFetcher, ctemp_process_t<T> dataProcessor,
               const boost::system::error_code errorCode)
{
    if (errorCode == boost::asio::error::operation_aborted || timer.expired())
    {
        std::cerr << "poll loop has been cancelled" << std::endl;
        return;
    }
    if (errorCode)
    {
        std::cerr << errorCode.message() << "\n";
        ::pollCtemp(std::move(timer), std::move(delay), dataFetcher,
                    dataProcessor);
        return;
    }

    dataFetcher(std::bind_front(detail::updateCtemp<T>, std::move(timer),
                                std::move(delay), dataProcessor, dataFetcher));
}

} // namespace detail

template <class T>
void pollCtemp(
    std::weak_ptr<boost::asio::steady_timer> weakTimer,
    std::chrono::duration<double, std::milli> delay,
    const std::function<void(std::function<void(const std::error_code&, T)>&&)>&
        dataFetcher,
    const std::function<void(const std::error_code& error, T data)>&
        dataProcessor)
{
    auto timer = weakTimer.lock();
    if (!timer)
    {
        return;
    }
    timer->expires_from_now(
        std::chrono::duration_cast<std::chrono::milliseconds>(delay));
    timer->async_wait(std::bind_front(detail::pollCtemp<T>, std::move(timer),
                                      std::move(delay), dataFetcher,
                                      dataProcessor));
}
