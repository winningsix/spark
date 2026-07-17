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
package org.apache.spark.sql.connector.catalog;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.apache.spark.annotation.Evolving;
import org.apache.spark.sql.types.StructField;
import org.apache.spark.sql.types.StructType;

/**
 * A view in a catalog.
 *
 * <p>This remains an interface for binary compatibility with Spark 4.x catalog plugins. The
 * default methods bridge the Spark 4.x view surface to the richer 4.2+ metadata surface, while
 * {@link Builder} retains the typed construction API used by current Spark internals.</p>
 *
 * @since 4.2.0
 */
@Evolving
public interface View extends Relation {

  // Spark 4.x catalog-plugin contract. Keeping these methods on an interface lets existing
  // implementations (notably Iceberg's SparkView) load unchanged on this snapshot runtime.
  String name();

  String query();

  String currentCatalog();

  String[] currentNamespace();

  StructType schema();

  String[] queryColumnNames();

  String[] columnAliases();

  String[] columnComments();

  @Override
  Map<String, String> properties();

  // Current Spark relation/view contract. Defaults adapt a Spark 4.x implementation without
  // requiring it to be recompiled.
  @Override
  default Column[] columns() {
    return CatalogV2Util.structTypeToV2Columns(schema(), true /* keep IDs */);
  }

  /** The SQL text of the view. */
  default String queryText() {
    return query();
  }

  default Map<String, String> sqlConfigs() {
    return Collections.emptyMap();
  }

  default String schemaMode() {
    return null;
  }

  default DependencyList viewDependencies() {
    return null;
  }

  /** Default implementation produced by {@link Builder}. */
  final class BuiltView implements View {
    private final Column[] columns;
    private final Map<String, String> properties;
    private final String queryText;
    private final String currentCatalog;
    private final String[] currentNamespace;
    private final Map<String, String> sqlConfigs;
    private final String schemaMode;
    private final String[] queryColumnNames;
    private final DependencyList viewDependencies;

    private BuiltView(Builder builder) {
      this.columns = builder.columns;
      this.properties = builder.properties;
      this.queryText = Objects.requireNonNull(builder.queryText, "queryText should not be null");
      this.currentCatalog = builder.currentCatalog;
      this.currentNamespace = builder.currentNamespace;
      this.sqlConfigs = Collections.unmodifiableMap(builder.sqlConfigs);
      this.schemaMode = builder.schemaMode;
      this.queryColumnNames = builder.queryColumnNames;
      this.viewDependencies = builder.viewDependencies;
      properties.putIfAbsent(TableCatalog.PROP_TABLE_TYPE, TableSummary.VIEW_TABLE_TYPE);
    }

    @Override
    public String name() {
      return "";
    }

    @Override
    public String query() {
      return queryText;
    }

    @Override
    public String queryText() {
      return queryText;
    }

    @Override
    public String currentCatalog() {
      return currentCatalog;
    }

    @Override
    public String[] currentNamespace() {
      return currentNamespace;
    }

    @Override
    public StructType schema() {
      return CatalogV2Util.v2ColumnsToStructType(columns);
    }

    @Override
    public Column[] columns() {
      return columns;
    }

    @Override
    public String[] queryColumnNames() {
      return queryColumnNames;
    }

    @Override
    public String[] columnAliases() {
      return queryColumnNames;
    }

    @Override
    public String[] columnComments() {
      StructField[] fields = schema().fields();
      String[] comments = new String[fields.length];
      for (int i = 0; i < fields.length; i++) {
        comments[i] = fields[i].getComment().isDefined() ? fields[i].getComment().get() : null;
      }
      return comments;
    }

    @Override
    public Map<String, String> properties() {
      return properties;
    }

    @Override
    public Map<String, String> sqlConfigs() {
      return sqlConfigs;
    }

    @Override
    public String schemaMode() {
      return schemaMode;
    }

    @Override
    public DependencyList viewDependencies() {
      return viewDependencies;
    }
  }

  class Builder extends RelationBuilder<Builder> {
    private String queryText;
    private String currentCatalog;
    private String[] currentNamespace = new String[0];
    private Map<String, String> sqlConfigs = new HashMap<>();
    private String schemaMode;
    private String[] queryColumnNames = new String[0];
    private DependencyList viewDependencies = null;

    @Override
    protected Builder self() {
      return this;
    }

    public Builder withQueryText(String queryText) {
      this.queryText = queryText;
      return this;
    }

    public Builder withCurrentCatalog(String currentCatalog) {
      this.currentCatalog = currentCatalog;
      return this;
    }

    public Builder withCurrentNamespace(String[] currentNamespace) {
      this.currentNamespace = currentNamespace == null ? new String[0] : currentNamespace;
      return this;
    }

    public Builder withSqlConfigs(Map<String, String> sqlConfigs) {
      this.sqlConfigs = new HashMap<>(sqlConfigs);
      return this;
    }

    public Builder withSchemaMode(String schemaMode) {
      this.schemaMode = schemaMode;
      return this;
    }

    public Builder withQueryColumnNames(String[] queryColumnNames) {
      this.queryColumnNames = queryColumnNames == null ? new String[0] : queryColumnNames;
      return this;
    }

    public Builder withViewDependencies(DependencyList viewDependencies) {
      this.viewDependencies = viewDependencies;
      return this;
    }

    public View build() {
      Objects.requireNonNull(columns, "columns should not be null");
      return new BuiltView(this);
    }
  }
}
