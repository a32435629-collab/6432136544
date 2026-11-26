#include "binary/BinaryFormats.hpp"
#include <algorithm>
#include <cstring>
namespace lulz::binary {
namespace {
std::string name8(const BinaryImage& im,std::size_t o){std::string s;for(std::size_t i=0;i<8&&im.contains(o+i,1)&&im.bytes()[o+i];++i)s.push_back(static_cast<char>(im.bytes()[o+i]));return s;}
void diag(FormatInfo& f,const char* code,const char* msg,std::size_t o){f.diagnostics.valid=false;f.diagnostics.diagnostics.push_back({code,msg,o});}
}
FormatInfo analyzeFormat(const BinaryImage& im){
 FormatInfo f; f.diagnostics=validateImage(im); BinaryView v(im);
 const auto& b=im.bytes();
 if(im.contains(0,4)&&b[0]=='M'&&b[1]=='Z'){
  f.format=Format::PE;
  auto pe=v.u32le(0x3c); if(!pe||!im.contains(*pe,24)||b[*pe]!='P'||b[*pe+1]!='E'||b[*pe+2]!=0||b[*pe+3]!=0){diag(f,"PE_BAD_SIGNATURE","Invalid or truncated PE signature",0x3c);return f;}
  auto coff=*pe+4; auto n=v.u16le(coff+2);auto opt=v.u16le(coff+16); if(!n||!opt||!im.contains(coff+20,*opt)){diag(f,"PE_TRUNCATED","Truncated COFF/optional header",coff);return f;}
  auto o=coff+20;auto magic=v.u16le(o);f.is64Bit=magic&&*magic==0x20b; if(!magic||(*magic!=0x10b&&*magic!=0x20b)){diag(f,"PE_BAD_OPTIONAL","Unsupported optional header",o);return f;}
  f.entryPoint=v.u32le(o+16).value_or(0);f.imageBase=f.is64Bit?v.u64le(o+24).value_or(0):v.u32le(o+28).value_or(0);
  auto dirOffset=o+(f.is64Bit?112:96);auto dirs=v.u32le(o+(f.is64Bit?108:92)).value_or(0);
  for(std::uint32_t i=0;i<std::min(dirs,16u)&&im.contains(dirOffset+i*8,8);++i){f.directories.push_back({i,v.u32le(dirOffset+i*8).value_or(0),v.u32le(dirOffset+i*8+4).value_or(0)});}
  auto table=o+*opt; if(!im.contains(table,static_cast<std::size_t>(*n)*40)){diag(f,"PE_SECTIONS_TRUNCATED","Section table extends beyond file",table);return f;}
  for(std::uint16_t i=0;i<*n;++i){auto s=table+i*40;auto vs=v.u32le(s+8).value_or(0),rs=v.u32le(s+16).value_or(0),ro=v.u32le(s+20).value_or(0),va=v.u32le(s+12).value_or(0),ch=v.u32le(s+36).value_or(0);f.sections.push_back({name8(im,s),ro,rs,va,vs,(ch&0x20000000)!=0});}
  f.valid=f.diagnostics.valid;return f;
 }
 if(im.contains(0,4)&&b[0]==0x7f&&b[1]=='E'&&b[2]=='L'&&b[3]=='F'){
  f.format=Format::ELF;f.is64Bit=b[4]==2;const bool le=b[5]==1;if(!le){diag(f,"ELF_ENDIAN_UNSUPPORTED","Only little-endian ELF supported in this slice",5);return f;}
  const auto eh=f.is64Bit?64u:52u;if(!im.contains(0,eh)){diag(f,"ELF_TRUNCATED","ELF header truncated",0);return f;}
  f.entryPoint=f.is64Bit?v.u64le(24).value_or(0):v.u32le(24).value_or(0);
  auto phoff=f.is64Bit?v.u64le(32).value_or(0):v.u32le(28).value_or(0);auto phentsize=v.u16le(f.is64Bit?54:42).value_or(0),phnum=v.u16le(f.is64Bit?56:44).value_or(0);
  for(unsigned i=0;i<phnum&&i<4096;++i){auto p=phoff+i*phentsize;if(!im.contains(p,phentsize)||phentsize<(f.is64Bit?56:32)){diag(f,"ELF_PH_TRUNCATED","Program header outside file",p);break;}auto type=v.u32le(p).value_or(0);if(type!=1)continue;auto off=f.is64Bit?v.u64le(p+8).value_or(0):v.u32le(p+4).value_or(0);auto addr=f.is64Bit?v.u64le(p+16).value_or(0):v.u32le(p+8).value_or(0);auto sz=f.is64Bit?v.u64le(p+32).value_or(0):v.u32le(p+16).value_or(0);auto flags=v.u32le(f.is64Bit?p+4:p+24).value_or(0);f.sections.push_back({"LOAD",off,sz,addr,sz,(flags&1)!=0});}
  f.valid=f.diagnostics.valid;return f;
 }
 if(im.contains(0,4)){auto m=v.u32le(0).value_or(0);if(m==0xfeedfacf||m==0xfeedface){f.format=Format::MachO;f.is64Bit=m==0xfeedfacf;auto n=v.u32le(16).value_or(0),cmdsz=v.u32le(20).value_or(0);auto p=f.is64Bit?32u:28u;if(!im.contains(0,p)||!im.contains(p,cmdsz)){diag(f,"MACHO_TRUNCATED","Mach-O load commands truncated",p);return f;}for(unsigned i=0;i<n&&i<4096;++i){auto cmd=v.u32le(p).value_or(0),sz=v.u32le(p+4).value_or(0);if(sz<8||!im.contains(p,sz)){diag(f,"MACHO_BAD_COMMAND","Invalid load command size",p);break;}if((cmd==0x19&&f.is64Bit)||(cmd==1&&!f.is64Bit)){auto segname=name8(im,p+8);auto vm=f.is64Bit?v.u64le(p+24).value_or(0):v.u32le(p+24).value_or(0);auto vms=f.is64Bit?v.u64le(p+32).value_or(0):v.u32le(p+28).value_or(0);auto fo=f.is64Bit?v.u64le(p+40).value_or(0):v.u32le(p+32).value_or(0);auto fs=f.is64Bit?v.u64le(p+48).value_or(0):v.u32le(p+36).value_or(0);auto fl=v.u32le(p+(f.is64Bit?64:56)).value_or(0);f.sections.push_back({segname,fo,fs,vm,vms,(fl&0x80000000)!=0});}p+=sz;}f.valid=f.diagnostics.valid;return f;}}
 diag(f,"FORMAT_UNKNOWN","Unrecognized binary format",0);return f;
}
std::optional<std::uint64_t> rvaToOffset(const FormatInfo& f,std::uint64_t r){if(f.format!=Format::PE)return {};for(auto&s:f.sections){auto span=std::max(s.size,s.virtualSize);if(r>=s.address&&r-s.address<span){auto d=r-s.address;if(d>=s.size)return {};return s.offset+d;}}return r<0x1000?std::optional<std::uint64_t>(r):std::nullopt;}
std::optional<std::uint64_t> offsetToRva(const FormatInfo& f,std::uint64_t o){for(auto&s:f.sections)if(o>=s.offset&&o-s.offset<s.size)return s.address+(o-s.offset);return o<0x1000?std::optional<std::uint64_t>(o):std::nullopt;}
std::optional<std::uint64_t> vaToRva(const FormatInfo& f,std::uint64_t va){if(va<f.imageBase)return {};return va-f.imageBase;}
std::vector<EmbeddedPayload> detectEmbeddedPayloads(const BinaryImage& im){std::vector<EmbeddedPayload> out;const auto& b=im.bytes();for(std::size_t i=0;i+4<=b.size();++i){if(b[i]=='M'&&b[i+1]=='Z')out.push_back({"PE",i});else if(b[i]==0x7f&&b[i+1]=='E'&&b[i+2]=='L'&&b[i+3]=='F')out.push_back({"ELF",i});else if(b[i]==0x50&&b[i+1]==0x4b&&b[i+2]==3&&b[i+3]==4)out.push_back({"ZIP",i});else if(b[i]==0x1f&&b[i+1]==0x8b)out.push_back({"GZIP",i});}return out;}
}
