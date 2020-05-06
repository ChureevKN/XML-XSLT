<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:output indent="yes" method="xml"/>
	<xsl:template match="/">
	
		<xsl:element name="Record">
			<xsl:for-each select="content/data/host/scan_objects/soft">
				
				<!--
				Three variables help hold the state of "for-each" results in inner scopes.
				-->
				<xsl:variable name="current_vulner_host_soft" select="name"/>
				<xsl:for-each select="vulners/vulner">
					<xsl:variable name="current_vulner_id_in_dictionary" select="@id"/>
					<xsl:variable name="current_vulner_in_dictionary" select="/content/vulners/vulner[./@id=$current_vulner_id_in_dictionary]"/>

					<Item>
						<ID_Уязвимости>
							<xsl:value-of select="@id">
							</xsl:value-of>
						</ID_Уязвимости>
						
						<Дата_публикации_уязвимости>
							<xsl:if test="string($current_vulner_in_dictionary/publication_date)">
								<xsl:value-of select="concat($current_vulner_in_dictionary/publication_date,'T00:00:00Z')">
								</xsl:value-of>
							</xsl:if>
						</Дата_публикации_уязвимости>
						
						<Уровень_опасности>
							<xsl:choose>
								<xsl:when test="@level='0'">
									<Item>Доступна информация</Item>
								</xsl:when>
								<xsl:when test="@level='1'">
									<Item>Низкий</Item>
								</xsl:when>
								<xsl:when test="@level='2'">
									<Item>Средний (подозрение)</Item>
								</xsl:when>
								<xsl:when test="@level='3'">
									<Item>Средний</Item>
								</xsl:when>
								<xsl:when test="@level='4'">
									<Item>Высокий (подозрение)</Item>
								</xsl:when>
								<xsl:when test="@level='5'">
									<Item>Высокий</Item>
								</xsl:when>
								<xsl:otherwise>
									<Item>(неверное значение параметра)</Item>
								</xsl:otherwise>
							</xsl:choose>
						</Уровень_опасности>
						
						<Базовая_оценка_CVSS>
							<xsl:value-of select="$current_vulner_in_dictionary/cvss/@base_score"/>
						</Базовая_оценка_CVSS>
						
						<Вектор_CVSS>
							<xsl:value-of select="$current_vulner_in_dictionary/cvss/@base_score_decomp"/>
						</Вектор_CVSS>
						
						<Название>
							<xsl:value-of select="$current_vulner_in_dictionary/title"/>
						</Название>
						
						<Краткое_описание>
							<xsl:value-of select="$current_vulner_in_dictionary/short_description"/>
						</Краткое_описание>
						
						<Решение>
							<xsl:value-of select="$current_vulner_in_dictionary/how_to_fix"/>
						</Решение>
						
						<Программное_обеспечение>
							<Item>
								<xsl:value-of select="$current_vulner_host_soft"/>
							</Item>
						</Программное_обеспечение>
					</Item>
				</xsl:for-each>
			</xsl:for-each>
		</xsl:element>
	</xsl:template>
</xsl:stylesheet>
