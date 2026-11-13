#include "NeuralNetwork.hpp"
#include <algorithm>
#include <bit>
#include <cmath>
#include <istream>
#include <limits>
#include <numeric>
#include <ostream>
#include <random>
#include <utility>
namespace lulz::ai::neural {
namespace {
constexpr std::uint8_t kMagic[]={'L','U','L','Z','N','N','0','1'};
constexpr std::uint32_t kVersion=1;
constexpr std::size_t kMaxLayers=64, kMaxNeurons=4096;
constexpr std::uint64_t kMaxParameters=16ull*1024ull*1024ull;
void err(std::string* out,const char* message){if(out)*out=message;}
bool validActivation(Activation a){return a==Activation::Linear||a==Activation::Relu||a==Activation::Tanh||a==Activation::Sigmoid;}
bool writeU32(std::ostream& o,std::uint32_t v){for(unsigned i=0;i<4;++i)o.put(static_cast<char>((v>>(8*i))&255));return bool(o);}
bool readU32(std::istream& in,std::uint32_t& v){v=0;for(unsigned i=0;i<4;++i){int b=in.get();if(b==std::char_traits<char>::eof())return false;v|=std::uint32_t(static_cast<unsigned char>(b))<<(8*i);}return true;}
bool writeDouble(std::ostream& o,double v){auto bits=std::bit_cast<std::uint64_t>(v);for(unsigned i=0;i<8;++i)o.put(static_cast<char>((bits>>(8*i))&255));return bool(o);}
bool readDouble(std::istream& in,double& v){std::uint64_t bits=0;for(unsigned i=0;i<8;++i){int b=in.get();if(b==std::char_traits<char>::eof())return false;bits|=std::uint64_t(static_cast<unsigned char>(b))<<(8*i);}v=std::bit_cast<double>(bits);return std::isfinite(v);}
}
NeuralNetwork::NeuralNetwork(std::vector<std::size_t> topology,Activation hidden,Activation output,std::uint32_t seed):topology_(std::move(topology)){
 if(topology_.size()<2||topology_.size()>kMaxLayers||!validActivation(hidden)||!validActivation(output))return;
 std::uint64_t params=0;for(auto n:topology_)if(n==0||n>kMaxNeurons)return;
 for(std::size_t i=1;i<topology_.size();++i){params+=std::uint64_t(topology_[i-1])*topology_[i]+topology_[i];if(params>kMaxParameters)return;}
 std::mt19937 rng(seed);layers_.reserve(topology_.size()-1);
 for(std::size_t i=1;i<topology_.size();++i){Layer l;l.inputCount=topology_[i-1];l.outputCount=topology_[i];l.activation=(i+1==topology_.size())?output:hidden;double lim=std::sqrt(6.0/double(l.inputCount+l.outputCount));std::uniform_real_distribution<double>d(-lim,lim);l.weights.resize(l.inputCount*l.outputCount);l.biases.assign(l.outputCount,0.0);for(auto& w:l.weights)w=d(rng);layers_.push_back(std::move(l));}
}
bool NeuralNetwork::valid()const noexcept{return topology_.size()>=2&&layers_.size()+1==topology_.size();}
std::size_t NeuralNetwork::inputSize()const noexcept{return valid()?topology_.front():0;}
std::size_t NeuralNetwork::outputSize()const noexcept{return valid()?topology_.back():0;}
const std::vector<std::size_t>& NeuralNetwork::topology()const noexcept{return topology_;}
double NeuralNetwork::activate(double x,Activation a)noexcept{switch(a){case Activation::Linear:return x;case Activation::Relu:return std::max(0.0,x);case Activation::Tanh:return std::tanh(x);case Activation::Sigmoid:if(x>=0){double z=std::exp(-std::min(x,709.0));return 1/(1+z);}else{double z=std::exp(std::max(x,-709.0));return z/(1+z);}}return x;}
double NeuralNetwork::derivative(double y,Activation a)noexcept{switch(a){case Activation::Linear:return 1;case Activation::Relu:return y>0?1:0;case Activation::Tanh:return 1-y*y;case Activation::Sigmoid:return y*(1-y);}return 0;}
std::optional<std::vector<double>> NeuralNetwork::forward(const std::vector<double>& input,std::vector<std::vector<double>>* acts,std::string* error)const{
 if(!valid()){err(error,"Neural network topology is invalid");return std::nullopt;}if(input.size()!=inputSize()){err(error,"Input vector size does not match network topology");return std::nullopt;}for(double x:input)if(!std::isfinite(x)){err(error,"Input contains a non-finite value");return std::nullopt;}
 std::vector<double> cur=input;if(acts){acts->clear();acts->push_back(cur);}for(const auto& l:layers_){std::vector<double> next(l.outputCount);for(std::size_t o=0;o<l.outputCount;++o){double sum=l.biases[o];for(std::size_t i=0;i<l.inputCount;++i)sum+=l.weights[o*l.inputCount+i]*cur[i];next[o]=activate(sum,l.activation);if(!std::isfinite(next[o])){err(error,"Forward pass produced a non-finite value");return std::nullopt;}}cur=std::move(next);if(acts)acts->push_back(cur);}return cur;
}
std::optional<std::vector<double>> NeuralNetwork::predict(const std::vector<double>& input,std::string* error)const{return forward(input,nullptr,error);}
double NeuralNetwork::loss(const std::vector<std::vector<double>>& xs,const std::vector<std::vector<double>>& ys)const{double sum=0;std::size_t n=0;for(std::size_t i=0;i<xs.size();++i){auto y=forward(xs[i],nullptr,nullptr);if(!y)return std::numeric_limits<double>::infinity();for(std::size_t j=0;j<y->size();++j){double d=(*y)[j]-ys[i][j];sum+=d*d;++n;}}return n?sum/double(n):0;}
std::optional<TrainingReport> NeuralNetwork::train(const std::vector<std::vector<double>>& xs,const std::vector<std::vector<double>>& ys,const TrainingOptions& opt,std::string* error){
 if(!valid()){err(error,"Neural network topology is invalid");return std::nullopt;}if(xs.empty()||xs.size()!=ys.size()){err(error,"Training inputs and targets must be non-empty and have equal sizes");return std::nullopt;}if(opt.epochs==0||opt.epochs>1000000||!std::isfinite(opt.learningRate)||opt.learningRate<=0||opt.learningRate>10){err(error,"Training options are outside supported limits");return std::nullopt;}
 for(std::size_t s=0;s<xs.size();++s){if(xs[s].size()!=inputSize()||ys[s].size()!=outputSize()){err(error,"Training sample dimensions do not match network topology");return std::nullopt;}for(double v:xs[s])if(!std::isfinite(v)){err(error,"Training input contains a non-finite value");return std::nullopt;}for(double v:ys[s])if(!std::isfinite(v)){err(error,"Training target contains a non-finite value");return std::nullopt;}}
 TrainingReport report;report.initialLoss=loss(xs,ys);std::vector<std::size_t> order(xs.size());std::iota(order.begin(),order.end(),0);std::mt19937 rng(opt.seed);std::vector<std::vector<double>> acts;std::vector<std::vector<double>> deltas(layers_.size());
 for(std::size_t epoch=0;epoch<opt.epochs;++epoch){if(opt.shuffle)std::shuffle(order.begin(),order.end(),rng);for(auto sample:order){auto out=forward(xs[sample],&acts,error);if(!out)return std::nullopt;
  for(std::size_t li=layers_.size();li-->0;){const auto& l=layers_[li];auto& delta=deltas[li];delta.assign(l.outputCount,0);for(std::size_t n=0;n<l.outputCount;++n){double propagated=0;if(li+1==layers_.size())propagated=(*out)[n]-ys[sample][n];else{const auto& next=layers_[li+1];for(std::size_t k=0;k<next.outputCount;++k)propagated+=next.weights[k*next.inputCount+n]*deltas[li+1][k];}delta[n]=propagated*derivative(acts[li+1][n],l.activation);}}
  for(std::size_t li=0;li<layers_.size();++li){auto& l=layers_[li];const auto& prev=acts[li];for(std::size_t o=0;o<l.outputCount;++o){auto offset=o*l.inputCount;for(std::size_t i=0;i<l.inputCount;++i)l.weights[offset+i]-=opt.learningRate*deltas[li][o]*prev[i];l.biases[o]-=opt.learningRate*deltas[li][o];}}
 }report.epochsCompleted=epoch+1;}report.finalLoss=loss(xs,ys);return report;
}
bool NeuralNetwork::save(std::ostream& out,std::string* error)const{
 if(!valid()){err(error,"Cannot save an invalid neural network");return false;}out.write(reinterpret_cast<const char*>(kMagic),sizeof(kMagic));if(!writeU32(out,kVersion)||!writeU32(out,std::uint32_t(topology_.size()))){err(error,"Failed to write neural model header");return false;}
 for(auto n:topology_)if(!writeU32(out,std::uint32_t(n))){err(error,"Failed to write neural model topology");return false;}
 for(const auto& l:layers_){out.put(static_cast<char>(l.activation));for(double v:l.weights)if(!writeDouble(out,v)){err(error,"Failed to write neural model weights");return false;}for(double v:l.biases)if(!writeDouble(out,v)){err(error,"Failed to write neural model biases");return false;}}
 if(!out){err(error,"Failed to write neural model");return false;}return true;
}
std::optional<NeuralNetwork> NeuralNetwork::load(std::istream& in,std::string* error){
 std::uint8_t magic[sizeof(kMagic)]{};in.read(reinterpret_cast<char*>(magic),sizeof(magic));if(!in||!std::equal(std::begin(kMagic),std::end(kMagic),std::begin(magic))){err(error,"Invalid neural model signature");return std::nullopt;}
 std::uint32_t version=0,count=0;if(!readU32(in,version)||version!=kVersion||!readU32(in,count)||count<2||count>kMaxLayers){err(error,"Unsupported or malformed neural model header");return std::nullopt;}
 std::vector<std::size_t> topology(count);for(auto& n:topology){std::uint32_t v=0;if(!readU32(in,v)||v==0||v>kMaxNeurons){err(error,"Invalid neural model topology");return std::nullopt;}n=v;}
 std::uint64_t params=0;for(std::size_t i=1;i<topology.size();++i){params+=std::uint64_t(topology[i-1])*topology[i]+topology[i];if(params>kMaxParameters){err(error,"Neural model exceeds parameter limit");return std::nullopt;}}
 NeuralNetwork model(topology);if(!model.valid()){err(error,"Invalid neural model topology");return std::nullopt;}
 for(auto& l:model.layers_){int a=in.get();if(a==std::char_traits<char>::eof()||!validActivation(static_cast<Activation>(a))){err(error,"Invalid neural model activation");return std::nullopt;}l.activation=static_cast<Activation>(a);for(auto& v:l.weights)if(!readDouble(in,v)){err(error,"Truncated or invalid neural model weights");return std::nullopt;}for(auto& v:l.biases)if(!readDouble(in,v)){err(error,"Truncated or invalid neural model biases");return std::nullopt;}}
 return model;
}
} // namespace lulz::ai::neural
