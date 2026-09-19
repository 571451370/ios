#ifndef PROTECT_SDK_IOS_H
#define PROTECT_SDK_IOS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 游戏盾 iOS SDK。必须在创建任何游戏 socket 之前调用 protect_start。
 *
 * config: JSON {"access_key":"后台 iOS 接入码"}，或直接传接入码字符串。
 * 返回: 0 成功；1 已启动；2 配置；3 拉节点；4 本机监听；5 hook 失败。
 */
int protect_start(const char *config);
void protect_stop(void);
int protect_running(void);
const char *protect_error_message(void);

#ifdef __cplusplus
}
#endif

#endif
