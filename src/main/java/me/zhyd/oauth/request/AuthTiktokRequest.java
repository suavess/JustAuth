package me.zhyd.oauth.request;

import com.alibaba.fastjson.JSONObject;
import com.xkcoding.http.support.HttpHeader;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.scope.AuthTiktokScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.HttpUtils;
import me.zhyd.oauth.utils.StringUtils;
import me.zhyd.oauth.utils.UrlBuilder;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;

/**
 * @author shunxin.jin
 * @date 2023/8/25 16:59
 */
public class AuthTiktokRequest extends AuthDefaultRequest {

    public AuthTiktokRequest(AuthConfig config) {
        super(config, AuthDefaultSource.TIKTOK);
    }

    public AuthTiktokRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.TIKTOK, authStateCache);
    }

    @Override
    protected AuthToken getAccessToken(AuthCallback authCallback) {
        Map<String, String> params = new HashMap<>(8);
        params.put("code", authCallback.getCode());
        params.put("grant_type", "authorization_code");
        params.put("redirect_uri", config.getRedirectUri());
        return this.getToken(source.accessToken(), params);
    }

    @Override
    protected AuthUser getUserInfo(AuthToken authToken) {
        String response = this.doGetUserInfo(authToken);
        JSONObject userInfoObject = JSONObject.parseObject(response);
        this.checkGetUserInfoResponse(userInfoObject);
        JSONObject data = userInfoObject.getJSONObject("data");
        JSONObject user = data.getJSONObject("user");
        return AuthUser.builder()
            .rawUserInfo(user)
            .uuid(user.getString("union_id"))
            .username(user.getString("open_id"))
            .nickname(user.getString("display_name"))
            .blog(user.getString("profile_deep_link"))
            .avatar(user.getString("avatar_url"))
            .remark(user.getString("bio_description"))
            .token(authToken)
            .source(source.toString())
            .build();
    }

    /**
     * 通用的 用户信息
     *
     * @param authToken token封装
     * @return Response
     */
    @Override
    protected String doGetUserInfo(AuthToken authToken) {
        HashMap<String, String> params = new HashMap<>(4);
        // 根据scope,设置需要取的数据， https://developers.tiktok.com/doc/tiktok-api-v2-get-user-info/
        String scopes = this.getScopes(",", true, AuthScopeUtils.getDefaultScopes(AuthTiktokScope.values()));
        StringJoiner fields = new StringJoiner(",");
        if (scopes.indexOf(AuthTiktokScope.USER_INFO_BASIC.getScope()) > 0) {
            fields.add("open_id").add("union_id").add("avatar_url").add("avatar_url_100").add("avatar_large_url").add("display_name");
        }
        if (scopes.indexOf(AuthTiktokScope.USER_INFO_PROFILE.getScope()) > 0) {
            fields.add("bio_description").add("profile_deep_link").add("is_verified");
        }
        if (scopes.indexOf(AuthTiktokScope.USER_INFO_STATS.getScope()) > 0) {
            fields.add("follower_count").add("following_count").add("likes_count").add("video_count");
        }
        params.put("fields", fields.toString());
        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add("Authorization", authToken.getTokenType() + " " + authToken.getAccessToken());
        return new HttpUtils().get(source.userInfo(), params, httpHeader, false).getBody();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkGetTokenResponse(JSONObject object) {
        String error = object.getString("error");
        if (StringUtils.isNotEmpty(error)) {
            throw new AuthException(object.getString("error_description"));
        }
    }

    private void checkGetUserInfoResponse(JSONObject object) {
        JSONObject errorObject = object.getJSONObject("error");
        if (Objects.nonNull(errorObject)) {
            String errorCode = errorObject.getString("code");
            if (!Objects.equals(errorCode, "ok")) {
                throw new AuthException(errorObject.getString("message"));
            }
        }
    }

    /**
     * 获取token，适用于获取access_token和刷新token
     *
     * @param accessTokenUrl 实际请求token的地址
     * @return token对象
     */
    private AuthToken getToken(String accessTokenUrl, Map<String, String> params) {
        params.put("client_key", config.getClientId());
        params.put("client_secret", config.getClientSecret());
        // 使用post请求,form encoding形式
        String response = new HttpUtils().post(accessTokenUrl, params, true).getBody();
        JSONObject object = JSONObject.parseObject(response);
        this.checkGetTokenResponse(object);
        return AuthToken.builder()
            .accessToken(object.getString("access_token"))
            .expireIn(object.getIntValue("expires_in"))
            .openId(object.getString("open_id"))
            .refreshTokenExpireIn(object.getInteger("refresh_expires_in"))
            .refreshToken(object.getString("refresh_token"))
            .scope(object.getString("scope"))
            .tokenType(object.getString("token_type"))
            .build();
    }

    /**
     * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return 返回授权地址
     * @since 1.9.3
     */
    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(source.authorize())
            .queryParam("response_type", "code")
            .queryParam("client_key", config.getClientId())
            .queryParam("redirect_uri", config.getRedirectUri())
            .queryParam("scope", this.getScopes(",", true, AuthScopeUtils.getDefaultScopes(AuthTiktokScope.values())))
            .queryParam("state", getRealState(state))
            .build();
    }

    /**
     * 刷新access token （续期）
     *
     * @param authToken 登录成功后返回的Token信息
     * @return AuthResponse
     */
    @Override
    public AuthResponse refresh(AuthToken authToken) {
        Map<String, String> params = new HashMap<>(8);
        params.put("grant_type", "refresh_token");
        params.put("refresh_token", authToken.getRefreshToken());
        return AuthResponse.builder()
            .code(AuthResponseStatus.SUCCESS.getCode())
            .data(this.getToken(source.accessToken(), params))
            .build();
    }
}
