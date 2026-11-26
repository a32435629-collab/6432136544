#include "binary/BinaryValidation.hpp"
namespace lulz::binary {
ValidationReport validateImage(const BinaryImage& image) {
 ValidationReport r;
 if(image.size()==0){r.valid=false;r.diagnostics.push_back({"BIN_EMPTY","Input is empty",0});}
 if(image.size()>0 && image.size()<4) r.diagnostics.push_back({"BIN_TRUNCATED_HEADER","File is shorter than common format signatures",0});
 return r;
}
}
