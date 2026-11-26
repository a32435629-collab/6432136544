#include "binary/BinaryImage.hpp"
#include "binary/BinaryView.hpp"
#include "binary/BinaryValidation.hpp"
#include <cassert>
int main(){
 using namespace lulz::binary;
 auto img=BinaryImage::fromBytes({0x34,0x12,0x78,0x56,0,0,0,0});
 BinaryView v(img);
 assert(v.u16le(0).value()==0x1234);
 assert(v.u32le(0).value()==0x56781234);
 assert(v.u64le(0).has_value());
 assert(!v.u64le(1).has_value());
 assert(img.contains(0,8)&&!img.contains(1,8));
 assert(validateImage(img).valid);
 assert(!validateImage(BinaryImage::fromBytes({})).valid);
}
