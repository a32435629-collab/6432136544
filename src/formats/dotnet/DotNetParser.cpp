#include "formats/dotnet/DotNetParser.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
namespace lulz::dotnet { namespace {
bool fits(std::size_t total,std::uint64_t off,std::uint64_t len){return off<=total&&len<=std::uint64_t(total)-off;}
template<class T> bool u(std::span<const std::uint8_t>b,std::uint64_t p,T&v){
 if(!fits(b.size(),p,sizeof(T)))return false; v=0;
 for(std::size_t i=0;i<sizeof(T);++i)v|=static_cast<T>(b[static_cast<std::size_t>(p)+i])<<(i*8);
 return true;
}
bool dir(std::span<const std::uint8_t>b,std::uint64_t p,DataDirectory&d){return u(b,p,d.rva)&&u(b,p+4,d.size);}
struct Section{std::uint32_t va=0,vs=0,raw=0,size=0;};
Result<std::size_t> mapRva(std::uint32_t rva,std::uint32_t len,const std::vector<Section>&ss,std::size_t file){
 for(const auto&s:ss){if(rva<s.va)continue;const std::uint64_t d=std::uint64_t(rva)-s.va;
  if(d>=std::max(s.vs,s.size))continue;
  if(d>s.size||len>std::uint64_t(s.size)-d)return Result<std::size_t>::failure("RVA is not backed by raw section data");
  const auto off=std::uint64_t(s.raw)+d;if(!fits(file,off,len))return Result<std::size_t>::failure("RVA maps outside file");
  return Result<std::size_t>::success(static_cast<std::size_t>(off));
 }return Result<std::size_t>::failure("RVA does not map to a section");
}
} // namespace
Result<Image> parse(std::span<const std::uint8_t>b){
 if(b.size()<64)return Result<Image>::failure("dotnet: truncated DOS header");
 std::uint16_t mz=0;if(!u(b,0,mz)||mz!=0x5a4d)return Result<Image>::failure("dotnet: invalid DOS signature");
 std::uint32_t pe32=0;if(!u(b,0x3c,pe32))return Result<Image>::failure("dotnet: truncated DOS header");
 const std::uint64_t pe=pe32;std::uint32_t sig=0;
 if(!u(b,pe,sig)||sig!=0x4550||!fits(b.size(),pe+4,20))return Result<Image>::failure("dotnet: invalid PE signature");
 Image out;std::uint16_t sectionsCount=0,optSize=0;
 if(!u(b,pe+4,out.machine)||!u(b,pe+6,sectionsCount)||!u(b,pe+20,optSize))return Result<Image>::failure("dotnet: malformed COFF header");
 if(sectionsCount>4096)return Result<Image>::failure("dotnet: unreasonable section count");
 const std::uint64_t opt=pe+24;if(optSize<2||!fits(b.size(),opt,optSize))return Result<Image>::failure("dotnet: truncated optional header");
 std::uint16_t magic=0;if(!u(b,opt,magic))return Result<Image>::failure("dotnet: missing optional-header magic");
 std::uint32_t count=0,numOff=0,dirOff=0;
 if(magic==0x10b){numOff=92;dirOff=96;if(optSize<96)return Result<Image>::failure("dotnet: PE32 optional header too small");}
 else if(magic==0x20b){out.pe32Plus=true;numOff=108;dirOff=112;if(optSize<112)return Result<Image>::failure("dotnet: PE32+ optional header too small");}
 else return Result<Image>::failure("dotnet: unsupported optional-header magic");
 if(!u(b,opt+16,out.peEntryPointRva)||!u(b,opt+numOff,count))return Result<Image>::failure("dotnet: truncated optional header");
 if(count<=14||dirOff+15ull*8>optSize)return Result<Image>::failure("dotnet: CLR directory entry is absent");
 DataDirectory clrDir;if(!dir(b,opt+dirOff+14*8,clrDir)||clrDir.rva==0||clrDir.size<72)return Result<Image>::failure("dotnet: CLR directory is absent or too small");
 const std::uint64_t st=opt+optSize;if(!fits(b.size(),st,std::uint64_t(sectionsCount)*40))return Result<Image>::failure("dotnet: truncated section table");
 std::vector<Section> ss;ss.reserve(sectionsCount);
 for(std::uint32_t i=0;i<sectionsCount;++i){const auto p=st+std::uint64_t(i)*40;Section s;
  if(!u(b,p+8,s.vs)||!u(b,p+12,s.va)||!u(b,p+16,s.size)||!u(b,p+20,s.raw))return Result<Image>::failure("dotnet: malformed section");
  if(s.size&&!fits(b.size(),s.raw,s.size))return Result<Image>::failure("dotnet: section data outside file");ss.push_back(s);
 }
 auto co=mapRva(clrDir.rva,72,ss,b.size());if(!co)return Result<Image>::failure("dotnet: "+co.error());
 const auto c=co.value();auto&h=out.clr;std::uint32_t cb=0;
 if(!u(b,c,cb)||cb<72||cb>clrDir.size||!fits(b.size(),c,cb))return Result<Image>::failure("dotnet: invalid CLR header size");
 h.headerSize=cb;
 if(!u(b,c+4,h.runtimeMajor)||!u(b,c+6,h.runtimeMinor)||!dir(b,c+8,h.metadata)||!u(b,c+16,h.flags)||!u(b,c+20,h.entryPointToken)||
 !dir(b,c+24,h.resources)||!dir(b,c+32,h.strongNameSignature)||!dir(b,c+40,h.codeManagerTable)||!dir(b,c+48,h.vtableFixups)||
 !dir(b,c+56,h.exportAddressTableJumps)||!dir(b,c+64,h.managedNativeHeader))return Result<Image>::failure("dotnet: truncated CLR header");
 out.hasIlOnlyFlag=(h.flags&1)!=0;out.requires32Bit=(h.flags&2)!=0;out.isStrongNameSigned=(h.flags&8)!=0;
 if(!h.metadata.rva||h.metadata.size<20)return Result<Image>::failure("dotnet: metadata directory missing");
 auto mo=mapRva(h.metadata.rva,h.metadata.size,ss,b.size());if(!mo)return Result<Image>::failure("dotnet metadata: "+mo.error());
 const auto m=mo.value();std::uint32_t root=0,verLen=0;std::uint16_t maj=0,min=0,res=0;
 if(!u(b,m,root)||root!=0x424a5342||!u(b,m+4,maj)||!u(b,m+6,min)||!u(b,m+8,res)||!u(b,m+12,verLen))
  return Result<Image>::failure("dotnet: invalid BSJB metadata root");
 (void)maj;(void)min;(void)res;
 if(!verLen||verLen>h.metadata.size-16||!fits(b.size(),m+16,verLen)||b[m+16+verLen-1]!=0)return Result<Image>::failure("dotnet: invalid metadata version string");
 out.metadataVersion.assign(reinterpret_cast<const char*>(b.data()+m+16),verLen-1);
 const std::uint64_t after=m+16+verLen,aligned=(after+3)&~std::uint64_t(3);
 std::uint16_t streamFlags=0,streamCount=0;
 if(aligned+4>m+h.metadata.size||!fits(b.size(),aligned,4)||!u(b,aligned,streamFlags)||!u(b,aligned+2,streamCount))return Result<Image>::failure("dotnet: truncated stream directory");
 (void)streamFlags;if(streamCount>64)return Result<Image>::failure("dotnet: unreasonable stream count");
 std::uint64_t cur=aligned+4;
 for(std::uint32_t i=0;i<streamCount;++i){std::uint32_t off=0,size=0;
  if(cur+8>m+h.metadata.size||!u(b,cur,off)||!u(b,cur+4,size))return Result<Image>::failure("dotnet: truncated stream header");cur+=8;
  std::string name;bool nul=false;
  for(std::size_t n=0;n<32&&cur<m+h.metadata.size;++n,++cur){auto ch=b[static_cast<std::size_t>(cur)];if(!ch){nul=true;++cur;break;}name.push_back(static_cast<char>(ch));}
  if(!nul)return Result<Image>::failure("dotnet: invalid stream name");cur=(cur+3)&~std::uint64_t(3);
  if(off>h.metadata.size||size>h.metadata.size-off||!fits(b.size(),m+off,size))return Result<Image>::failure("dotnet: stream exceeds metadata root");
  if(std::any_of(out.streams.begin(),out.streams.end(),[&](const MetadataStream&s){return s.name==name;}))return Result<Image>::failure("dotnet: duplicate stream name");
  out.streams.push_back({std::move(name),off,size});
 }
 auto ti=std::find_if(out.streams.begin(),out.streams.end(),[](const MetadataStream&s){return s.name=="#~"||s.name=="#-";});
 if(ti!=out.streams.end()){const std::uint64_t t=m+ti->offset;if(ti->size<24)return Result<Image>::failure("dotnet: tables stream too small");
  std::uint64_t valid=0,sorted=0;std::uint8_t heap=0;
  if(!u(b,t+6,heap)||!u(b,t+8,valid)||!u(b,t+16,sorted))return Result<Image>::failure("dotnet: malformed tables header");
  (void)heap;(void)sorted;std::uint64_t row=t+24;
  for(std::uint8_t id=0;id<64;++id)if(valid&(std::uint64_t(1)<<id)){std::uint32_t n=0;
   if(row+4>t+ti->size||!u(b,row,n))return Result<Image>::failure("dotnet: truncated table row counts");
   row+=4;out.tables.push_back({id,n});
  }
 }
 return Result<Image>::success(std::move(out));
}
} // namespace lulz::dotnet
