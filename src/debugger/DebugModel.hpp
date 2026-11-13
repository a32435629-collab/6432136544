#pragma once
#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace lulz::debugger {
enum class ProcessState { Detached, Attached, Running, Paused, Exited };
enum class EventKind { Breakpoint, SingleStep, Exception, ThreadCreated, ThreadExited, ProcessExited };
struct DebugEvent { EventKind kind{}; std::uint64_t address{}; std::uint32_t threadId{}; std::uint32_t code{}; };
struct Breakpoint { std::uint64_t address{}; bool enabled{true}; std::string label; };
class DebugSessionModel {
public:
    ProcessState state() const noexcept { return state_; }
    bool attach(std::uint32_t pid) {
        if(pid==0 || state_!=ProcessState::Detached) return false;
        pid_=pid; state_=ProcessState::Attached; return true;
    }
    bool detach() {
        if(state_==ProcessState::Detached) return false;
        pid_=0; state_=ProcessState::Detached; events_.clear(); return true;
    }
    bool resume() { if(state_!=ProcessState::Paused && state_!=ProcessState::Attached) return false; state_=ProcessState::Running; return true; }
    bool pause() { if(state_!=ProcessState::Running) return false; state_=ProcessState::Paused; return true; }
    bool markExited() { if(state_==ProcessState::Detached) return false; state_=ProcessState::Exited; return true; }
    bool addBreakpoint(Breakpoint bp) {
        if(bp.address==0) return false; return breakpoints_.insert_or_assign(bp.address,std::move(bp)).second;
    }
    bool removeBreakpoint(std::uint64_t address) { return breakpoints_.erase(address)!=0; }
    std::optional<Breakpoint> breakpointAt(std::uint64_t address) const {
        auto it=breakpoints_.find(address); if(it==breakpoints_.end()) return std::nullopt; return it->second;
    }
    bool pushEvent(DebugEvent event, std::size_t maxEvents=4096) {
        if(state_==ProcessState::Detached || events_.size()>=maxEvents) return false;
        events_.push_back(event); return true;
    }
    const std::vector<DebugEvent>& events() const noexcept { return events_; }
    std::uint32_t processId() const noexcept { return pid_; }
private:
    ProcessState state_{ProcessState::Detached};
    std::uint32_t pid_{};
    std::unordered_map<std::uint64_t,Breakpoint> breakpoints_;
    std::vector<DebugEvent> events_;
};
} // namespace lulz::debugger
