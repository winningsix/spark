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

import java.io.{InputStream, OutputStream}
import java.util.Properties
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}

import org.apache.commons.crypto.random._
import org.apache.commons.crypto.stream._

import org.apache.spark.SparkConf
import org.apache.spark.crypto.CryptoConf._
import org.apache.spark.deploy.SparkHadoopUtil

/**
 * A util class for manipulating file shuffle encryption and decryption streams.
 */
private[spark] object CryptoStreamUtils {
  // The initialization vector length in bytes.
  val IV_LENGTH_IN_BYTES = 16
  // The prefix of Crypto related configurations in Spark configuration.
  val SPARK_COMMONS_CRYPTO_CONF_PREFIX = "spark.commons.crypto."
  // The prefix for the configurations passing to Commons-crypto library.
  val COMMONS_CRYPTO_CONF_PREFIX = "commons.crypto."


  /**
   * Helper method to wrap [[OutputStream]] with [[CryptoOutputStream]] for encryption.
   */
  def createCryptoOutputStream(
      os: OutputStream,
      sparkConf: SparkConf): OutputStream = {
    val properties = toCryptoConf(sparkConf, SPARK_COMMONS_CRYPTO_CONF_PREFIX,
      COMMONS_CRYPTO_CONF_PREFIX)
    val iv: Array[Byte] = createInitializationVector(properties)
    os.write(iv)
    val credentials = SparkHadoopUtil.get.getCurrentUserCredentials()
    val key = credentials.getSecretKey(SPARK_SHUFFLE_TOKEN)
    val transformationStr = sparkConf.get(
      "spark.shuffle.crypto.cipher.transformation", "AES/CTR/NoPadding")
    new CryptoOutputStream(transformationStr, properties, os,
      new SecretKeySpec(key, "AES"), new IvParameterSpec(iv))
  }

  /**
   * Helper method to wrap [[InputStream]] with [[CryptoInputStream]] for decryption.
   */
  def createCryptoInputStream(
      is: InputStream,
      sparkConf: SparkConf): InputStream = {
    val properties = toCryptoConf(sparkConf, SPARK_COMMONS_CRYPTO_CONF_PREFIX,
      COMMONS_CRYPTO_CONF_PREFIX)
    val iv = new Array[Byte](IV_LENGTH_IN_BYTES)
    is.read(iv, 0, iv.length)
    val credentials = SparkHadoopUtil.get.getCurrentUserCredentials()
    val key = credentials.getSecretKey(SPARK_SHUFFLE_TOKEN)
    val transformationStr = sparkConf.get(
      "spark.shuffle.crypto.cipher.transformation", "AES/CTR/NoPadding")
    new CryptoInputStream(transformationStr, properties, is,
      new SecretKeySpec(key, "AES"), new IvParameterSpec(iv))
  }

  /**
   * Get Commons-crypto configurations from Spark configurations identified
   * by prefix.
   */
  def toCryptoConf(
      conf: SparkConf,
      sparkPrefix: String,
      cryptoPrefix: String): Properties = {
    val props = new Properties()
    conf.getAll.foreach { case (k, v) =>
      if (k.startsWith(sparkPrefix)) {
        props.put(COMMONS_CRYPTO_CONF_PREFIX + k.substring(
          SPARK_COMMONS_CRYPTO_CONF_PREFIX.length()), v)
      }
    }
    props
  }

  /**
   * This method to generate an IV (Initialization Vector) using secure random.
   */
  private[this] def createInitializationVector(properties: Properties): Array[Byte] = {
    val iv = new Array[Byte](IV_LENGTH_IN_BYTES)
    CryptoRandomFactory.getCryptoRandom(properties).nextBytes(iv)
    iv
  }
}
