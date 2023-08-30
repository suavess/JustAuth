package me.zhyd.oauth.enums.scope;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * @author shunxin.jin
 * @date 2023/8/30 15:31
 */
@Getter
@AllArgsConstructor
public enum AuthTiktokScope implements AuthScope {
    //
    USER_INFO_BASIC("user.info.basic", "Read a user's profile info (open id, avatar, display name ...)", true),
    USER_INFO_PROFILE("user.info.profile", "Read access to profile_web_link, profile_deep_link, bio_description, is_verified.", false),
    USER_INFO_STATS("user.info.stats", "", false)
    ;

    private final String scope;
    private final String description;
    private final boolean isDefault;
}
