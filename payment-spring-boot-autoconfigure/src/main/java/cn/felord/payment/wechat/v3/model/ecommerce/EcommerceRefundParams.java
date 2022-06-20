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

package cn.felord.payment.wechat.v3.model.ecommerce;

import lombok.Data;

/**
 * @author felord.cn
 * @since 1.0.14.RELEASE
 */
@Data
public class EcommerceRefundParams {
    private String subMchid;
    private String spAppid;
    private String subAppid;
    private String transactionId;
    private String outTradeNo;
    private String outRefundNo;
    private String reason;
    private EcommerceAmount amount;
    private String notifyUrl;
    private String refundAccount;
    private String fundsAccount;
}
