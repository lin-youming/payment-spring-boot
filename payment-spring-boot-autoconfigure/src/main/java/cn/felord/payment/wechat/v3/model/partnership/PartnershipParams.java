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

package cn.felord.payment.wechat.v3.model.partnership;

import lombok.Getter;
import lombok.ToString;

/**
 * @author felord.cn
 * @since 1.0.16.RELEASE
 */
@ToString
@Getter
public class PartnershipParams {
    private String idempotencyKey;
    private final Partner partner;
    private final AuthorizedData authorizedData;

    public PartnershipParams(String idempotencyKey, Partner partner, AuthorizedData authorizedData) {
        this.idempotencyKey = idempotencyKey;
        this.partner = partner;
        this.authorizedData = authorizedData;
    }

    public void clearKey() {
        this.idempotencyKey = null;
    }
}
