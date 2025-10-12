package io.github.herbpot.miyobackend.domain.community.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.locationtech.jts.geom.*;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * RegionBoundaryService
 * - GeoJSON 파일로부터 한국 시/군/구 행정구역 경계 데이터 로드
 * - 특정 좌표가 특정 행정구역 내에 있는지 검사 (Point-in-Polygon)
 * - 애플리케이션 시작 시 GeoJSON 파일을 메모리에 로드
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RegionBoundaryService {

    private final ObjectMapper objectMapper;
    private static final GeometryFactory GEOMETRY_FACTORY = new GeometryFactory(new PrecisionModel(), 4326);

    /**
     * 지역명 -> Polygon 매핑
     * - Key: 시/군/구명 (예: "종로구", "강남구")
     * - Value: JTS Polygon 객체
     */
    private final Map<String, Polygon> regionBoundaries = new HashMap<>();

    /**
     * 애플리케이션 시작 시 GeoJSON 파일 로드
     * - korea_basic_local_gorvernment_boundary.geojson 파일 읽기
     * - 각 Feature의 SIG_KOR_NM(시군구명)과 Polygon 추출
     * - regionBoundaries Map에 저장
     */
    @PostConstruct
    public void loadGeoJsonData() {
        try {
            log.info("Loading Korea region boundary GeoJSON data...");

            ClassPathResource resource = new ClassPathResource("korea_basic_local_gorvernment_boundary.geojson");
            InputStream inputStream = resource.getInputStream();

            JsonNode root = objectMapper.readTree(inputStream);
            JsonNode features = root.get("features");

            int loadedCount = 0;

            for (JsonNode feature : features) {
                // 지역명 추출 (SIG_KOR_NM)
                String regionName = feature.get("properties").get("SIG_KOR_NM").asText();

                // Geometry 추출
                JsonNode geometryNode = feature.get("geometry");
                String geometryType = geometryNode.get("type").asText();

                if ("Polygon".equals(geometryType)) {
                    Polygon polygon = parsePolygon(geometryNode);
                    regionBoundaries.put(regionName, polygon);
                    loadedCount++;
                }
            }

            log.info("Successfully loaded {} region boundaries", loadedCount);

        } catch (IOException e) {
            log.error("Failed to load GeoJSON data: {}", e.getMessage(), e);
            throw new RuntimeException("GeoJSON 파일을 로드하는 데 실패했습니다.", e);
        }
    }

    /**
     * GeoJSON Polygon을 JTS Polygon 객체로 변환
     * - coordinates 배열을 파싱하여 Coordinate[] 생성
     * - LinearRing 생성 후 Polygon 반환
     *
     * @param geometryNode GeoJSON Geometry 노드
     * @return JTS Polygon 객체
     */
    private Polygon parsePolygon(JsonNode geometryNode) {
        JsonNode coordinatesArray = geometryNode.get("coordinates").get(0); // 외부 링만 사용

        Coordinate[] coordinates = new Coordinate[coordinatesArray.size()];

        for (int i = 0; i < coordinatesArray.size(); i++) {
            JsonNode coord = coordinatesArray.get(i);
            double lng = coord.get(0).asDouble();
            double lat = coord.get(1).asDouble();
            coordinates[i] = new Coordinate(lng, lat);
        }

        LinearRing shell = GEOMETRY_FACTORY.createLinearRing(coordinates);
        return GEOMETRY_FACTORY.createPolygon(shell);
    }

    /**
     * 특정 좌표가 특정 행정구역 내에 있는지 검사
     * - Point-in-Polygon 알고리즘 사용 (JTS contains 메서드)
     *
     * @param regionName 행정구역명 (예: "종로구", "강남구")
     * @param latitude 위도
     * @param longitude 경도
     * @return true: 해당 구역 내, false: 해당 구역 외 또는 구역 정보 없음
     */
    public boolean isPointInRegion(String regionName, double latitude, double longitude) {
        Polygon polygon = regionBoundaries.get(regionName);

        if (polygon == null) {
            log.warn("Region boundary not found: {}", regionName);
            return false;
        }

        Point point = GEOMETRY_FACTORY.createPoint(new Coordinate(longitude, latitude));
        return polygon.contains(point);
    }

    /**
     * 로드된 모든 지역명 목록 반환
     * - 디버깅 및 검증용
     *
     * @return 지역명 Set
     */
    public java.util.Set<String> getAvailableRegions() {
        return regionBoundaries.keySet();
    }
}
