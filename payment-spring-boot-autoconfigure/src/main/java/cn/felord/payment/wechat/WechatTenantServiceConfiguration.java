/*
 *  Copyright 2019-2022 felord.cn
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       https://www.apache.org/licenses/LICENSE-2.0
 *  Website:
 *       https://felord.cn
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package cn.felord.payment.wechat;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;

/**
 * The type Wechat tenant service configuration.
 *
 * @author felord.cn
 * @since 1.0.16.RELEASE
 */
@Configuration(proxyBeanMethods = false)
@Conditional(WechatPayConfiguredCondition.class)
@EnableConfigurationProperties(WechatPayProperties.class)
public class WechatTenantServiceConfiguration {

    /**
     * Wechat tenant service wechat tenant service.
     *
     * @param wechatPayProperties the wechat pay properties
     * @return the wechat tenant service
     */
    @Bean
    @ConditionalOnMissingBean
    public WechatTenantService wechatTenantService(WechatPayProperties wechatPayProperties) {
        return new InMemoryWechatTenantService(wechatPayProperties);
    }
}
