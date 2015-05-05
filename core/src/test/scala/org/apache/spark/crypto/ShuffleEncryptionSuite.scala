/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.spark.crypto

import java.security.PrivilegedExceptionAction

import org.apache.hadoop.security.{Credentials, UserGroupInformation}

import org.apache.spark.{SparkConf, SparkFunSuite}
import org.apache.spark.crypto.CryptoConf._
import org.apache.spark.crypto.CryptoStreamUtils.{COMMONS_CRYPTO_CONF_PREFIX, SPARK_COMMONS_CRYPTO_CONF_PREFIX}


private[spark] class ShuffleEncryptionSuite extends SparkFunSuite {
  val ugi = UserGroupInformation.createUserForTesting("testuser", Array("testgroup"))

  test("Crypto configuration conversion") {
    val sparkKey1 = s"${SPARK_COMMONS_CRYPTO_CONF_PREFIX}a.b.c"
    val sparkVal1 = "val1"
    val cryptoKey1 = s"${COMMONS_CRYPTO_CONF_PREFIX}a.b.c"

    val sparkKey2 = SPARK_COMMONS_CRYPTO_CONF_PREFIX.stripSuffix(".") + "A.b.c"
    val sparkVal2 = "val2"
    val cryptoKey2 = s"${COMMONS_CRYPTO_CONF_PREFIX}A.b.c"
    val conf = new SparkConf()
    conf.set(sparkKey1, sparkVal1)
    conf.set(sparkKey2, sparkVal2)
    val props = CryptoStreamUtils.toCryptoConf(conf, SPARK_COMMONS_CRYPTO_CONF_PREFIX,
      COMMONS_CRYPTO_CONF_PREFIX)
    assert(props.getProperty(cryptoKey1) === sparkVal1)
    assert(!props.containsKey(cryptoKey2))
  }

  test("Shuffle encryption is disabled by default") {
    ugi.doAs(new PrivilegedExceptionAction[Unit]() {
      override def run(): Unit = {
        val credentials = UserGroupInformation.getCurrentUser.getCredentials()
        val conf = new SparkConf()
        initCredentials(conf, credentials)
        assert(credentials.getSecretKey(SPARK_SHUFFLE_TOKEN) === null)
      }
    })
  }

  test("Shuffle encryption key length should be 128 by default") {
    ugi.doAs(new PrivilegedExceptionAction[Unit]() {
      override def run(): Unit = {
        val credentials = UserGroupInformation.getCurrentUser.getCredentials()
        val conf = new SparkConf()
        conf.set(SPARK_SHUFFLE_ENCRYPTION_ENABLED, true.toString)
        initCredentials(conf, credentials)
        var key = credentials.getSecretKey(SPARK_SHUFFLE_TOKEN)
        assert(key !== null)
        val actual = key.length * (java.lang.Byte.SIZE)
        assert(actual === DEFAULT_SPARK_SHUFFLE_ENCRYPTION_KEY_SIZE_BITS)
      }
    })
  }

  test("Initial credentials with key length in 256") {
    ugi.doAs(new PrivilegedExceptionAction[Unit]() {
      override def run(): Unit = {
        val credentials = UserGroupInformation.getCurrentUser.getCredentials()
        val conf = new SparkConf()
        conf.set(SPARK_SHUFFLE_ENCRYPTION_KEY_SIZE_BITS, 256.toString)
        conf.set(SPARK_SHUFFLE_ENCRYPTION_ENABLED, true.toString)
        initCredentials(conf, credentials)
        var key = credentials.getSecretKey(SPARK_SHUFFLE_TOKEN)
        assert(key !== null)
        val actual = key.length * (java.lang.Byte.SIZE)
        assert(actual === 256)
      }
    })
  }

  test("Initial credentials with invalid key length") {
    ugi.doAs(new PrivilegedExceptionAction[Unit]() {
      override def run(): Unit = {
        val credentials = UserGroupInformation.getCurrentUser.getCredentials()
        val conf = new SparkConf()
        conf.set(SPARK_SHUFFLE_ENCRYPTION_KEY_SIZE_BITS, 328.toString)
        conf.set(SPARK_SHUFFLE_ENCRYPTION_ENABLED, true.toString)
        val thrown = intercept[IllegalArgumentException] {
          initCredentials(conf, credentials)
        }
      }
    })
  }

  private[this] def initCredentials(conf: SparkConf, credentials: Credentials): Unit = {
    if (CryptoConf.isShuffleEncryptionEnabled(conf)) {
      CryptoConf.initSparkShuffleCredentials(conf, credentials)
    }
  }
}
