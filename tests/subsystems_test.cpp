#include "compression/Compression.hpp"
#include "crypto_analysis/CryptoAnalysis.hpp"
#include "database/AnalysisStore.hpp"
#include "debugger/DebugModel.hpp"
#include "decompiler/IR.hpp"
#include "diff/BinaryDiff.hpp"
#include <array>
#include <cassert>
#include <cstdint>
#include <vector>

int main() {
    const std::array<std::uint8_t,12> source{1,1,1,1,2,3,4,5,5,5,8,9};
    const auto packed=lulz::compression::encodeRle(source);
    std::vector<std::uint8_t> restored;
    assert(lulz::compression::decodeRle(packed,restored));
    assert(std::equal(source.begin(),source.end(),restored.begin(),restored.end()));
    const std::array<std::uint8_t,2> bad{0x02,0x44};
    assert(!lulz::compression::decodeRle(bad,restored));

    const std::array<std::uint8_t,4> zeros{0,0,0,0};
    const auto stats=lulz::crypto_analysis::analyzeBytes(zeros);
    assert(stats.entropyBits==0.0 && stats.size==4);
    const auto xorCandidates=lulz::crypto_analysis::rankSingleByteXor(zeros,4);
    assert(!xorCandidates.empty());

    lulz::database::AnalysisStore store;
    assert(store.insert({1,"sample.exe","PE","abc",12,{"test"}}));
    assert(!store.insert({1,"duplicate","PE","",0,{}}));
    assert(store.find(1).has_value());
    assert(store.findByTag("test").size()==1);
    assert(store.erase(1) && store.size()==0);

    lulz::debugger::DebugSessionModel session;
    assert(session.attach(42));
    assert(session.addBreakpoint({0x1000,true,"entry"}));
    assert(session.resume() && session.pause());
    assert(session.pushEvent({lulz::debugger::EventKind::Breakpoint,0x1000,1,0}));
    assert(session.events().size()==1);
    assert(session.detach());

    lulz::decompiler::FunctionIR ir{"sample",{{lulz::decompiler::OpKind::Assign,"x","1","",0},
        {lulz::decompiler::OpKind::Return,"","x","",0}}};
    const auto pseudo=lulz::decompiler::emitPseudoCode(ir);
    assert(pseudo.find("return x;")!=std::string::npos);

    const std::array<std::uint8_t,4> a{1,2,3,4}, b{1,9,3,5};
    const auto delta=lulz::diff::compareBytes(a,b);
    assert(delta.changedBytes==2 && delta.changed.size()==2 && !delta.identical());
}
