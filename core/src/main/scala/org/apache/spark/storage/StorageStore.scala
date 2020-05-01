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

package org.apache.spark.storage

/**
 * Storage store primitive API. It provides two sets of APIs: 1. Non ID based; 2. ID based.
 */
trait StorageStore {

  ///////////////////////////////////////////////////////////////////////////
  // Non ID based
  ///////////////////////////////////////////////////////////////////////////
  def allocate(size: Long): Long

  def free(address: Long): Boolean


  ///////////////////////////////////////////////////////////////////////////
  // ID based
  ///////////////////////////////////////////////////////////////////////////

  // FIXME avoid passing in ID??
  def allocate(id: Array[Byte], size: Long): Long

  def get(id: Array[Byte]): Long

  // FIXME remote this?
  def prefetchIfNotPresent(id: Array[Byte]): Long

  def contains(id: Array[Byte]): Boolean

  def remove(id: Array[Byte]): Boolean

  def release(id: Array[Byte]): Boolean

  // FIXME remote this?
  def seal(id: Array[Byte]): Boolean

}
