# Goal
以`https://github.com/kylecui/jzzn`里`docs`的内容为设计目标，以`https://github.com/kylecui/rswitch/`的`dev`分支下的`docs`描述的Reconfigurable Switch为底层框架，基于`https://github.com/kylecui/rswitch/`的`dev`分支提供的平台，重新设计和实现我们设计目标中的网络设备。我们需要具备的能力包括但不限于：
1. 动态诱捕：动态生成诱饵，诱捕网络中潜在的嗅探行为
2. 流量编织：可以动态调整策略，将部分流量诱捕到更完善的蜜罐中；或者将部分设备的流量镜像供DPI分析
3. 数据整理：快速分析显然的威胁，数据收集并具备上传到分析平台的能力
4. 配置信息下发：能够接受平台下发的配置
5. 背景收集：能够收集网络背景噪声（各种广播、组播、协议流量等）供分析平台分析本地数据。