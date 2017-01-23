package io.pivotal.security.data;

import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedSecretImpl;
import io.pivotal.security.repository.PasswordRepository;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.service.EncryptionKeyService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Slice;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static io.pivotal.security.repository.SecretRepository.BATCH_SIZE;

@Service
public class SecretDataService {
  private static final String FIND_MOST_RECENT_BY_SUBSTRING_QUERY =
    "SELECT DISTINCT " +
      "name, " +
      "version_created_at " +
    "FROM " +
      "named_secret " +
    "INNER JOIN ( " +
      "SELECT " +
        "UPPER(name) AS inner_name, " +
        "MAX(version_created_at) AS inner_version_created_at " +
      "FROM " +
        "named_secret " +
      "GROUP BY " +
        "UPPER(name) " +
    ") AS most_recent " +
    "ON " +
      "named_secret.version_created_at = most_recent.inner_version_created_at " +
    "AND " +
      "UPPER(named_secret.name) = most_recent.inner_name " +
    "WHERE " +
      "UPPER(named_secret.name) LIKE UPPER(?) OR UPPER(named_secret.name) LIKE UPPER(?) " +
    "ORDER BY version_created_at DESC";

  private final SecretRepository secretRepository;
  private final JdbcTemplate jdbcTemplate;
  private final EncryptionKeyService encryptionKeyService;
  private final PasswordRepository passwordRepository;
  private final EntityManager entityManager;

  @Autowired
  SecretDataService(
      SecretRepository secretRepository,
      PasswordRepository passwordRepository,
      JdbcTemplate jdbcTemplate,
      EncryptionKeyService encryptionKeyService,
      EntityManager entityManager
  ) {
    this.secretRepository = secretRepository;
    this.jdbcTemplate = jdbcTemplate;
    this.encryptionKeyService = encryptionKeyService;
    this.passwordRepository = passwordRepository;
    this.entityManager = entityManager;
  }

  public <Z extends NamedSecret> Z save(Z namedSecret) {
    if (namedSecret.getEncryptionKeyUuid() == null) {
      namedSecret.setEncryptionKeyUuid(encryptionKeyService.getActiveEncryptionKeyUuid());
    }
    return secretRepository.saveAndFlush(namedSecret);
  }

  public List<String> findAllPaths() {
    return secretRepository.findAllPaths(true);
  }

  public NamedSecret findMostRecent(String name) {
    return secretRepository.findFirstByNameIgnoreCaseOrderByVersionCreatedAtDesc(name);
  }

  public NamedSecret findByUuid(String uuid) {
    return secretRepository.findOneByUuid(UUID.fromString(uuid));
  }

  public List<NamedSecret> findContainingName(String name) {
    return findMostRecentLikeSubstrings('%' + name + '%', StringUtils.stripStart(name, "/") + '%');
  }

  public List<NamedSecret> findStartingWithName(String name) {
    if (!name.endsWith("/")) {
      name += '/';
    }
    name += '%';

    return findMostRecentLikeSubstrings(name, name);
  }

  public List<NamedSecret> delete(String name) {
    return secretRepository.deleteByNameIgnoreCase(name);
  }

  public List<NamedSecret> findAllByName(String name) {
    return secretRepository.findAllByNameIgnoreCase(name);
  }

  private List<NamedSecret> findMostRecentLikeSubstrings(String substring1, String substring2) {
    secretRepository.flush();

    // The subquery gets us the right name/version_created_at pairs, but changes the capitalization of the names.
    return jdbcTemplate.query(
        FIND_MOST_RECENT_BY_SUBSTRING_QUERY,
      new Object[] {substring1, substring2},
      (rowSet, rowNum) -> {
        NamedSecret secret = new NamedSecretImpl();

        secret.setName(rowSet.getString("name"));
        secret.setVersionCreatedAt(Instant.ofEpochMilli(rowSet.getLong("version_created_at")));

        return secret;
      }
    );
  }

  public Slice<NamedSecret> findAllNotEncryptedByActiveKey() {
    return secretRepository.findByEncryptionKeyUuidNot(encryptionKeyService.getActiveEncryptionKeyUuid(), new PageRequest(0, BATCH_SIZE));
//    Stream<NamedSecret> stream = StreamSupport.
//    Spliterator<NamedSecret> spliterator = Spliterators.spliterator()
//    return page.getContent();
  }

//  public Stream<NamedSecret> streamAllNotEncryptedByActiveKey() {
//    StatelessSession session = ((Session) entityManager.getDelegate()).getSessionFactory().openStatelessSession();
////    Connection connection;
////    try {
////      connection = jdbcTemplate.getDataSource().getConnection();
////      PreparedStatement statement = connection.prepareStatement("select * from named_secret where encryption_key_uuid is not ?");
////      statement.setObject(1, encryptionKeyService.getActiveEncryptionKeyUuid());
////      session.createSQLQuery("select * from named_secret where encryption_key_uuid is not ?").addEntity(encryptionKeyService.getActiveEncryptionKeyUuid());
////    } catch (SQLException e) {
////      throw new RuntimeException(e);
////    }
//    final Query query = session.createSQLQuery("select * from named_secret where encryption_key_uuid <> :foo")
//        .setParameter("foo", encryptionKeyService.getActiveEncryptionKeyUuid());
////    final org.hibernate.Query query = session.createQuery("select * from named_secret where encryption_key_uuid is not ?");
////    query.setParameter("encryptionKeyUuid", encryptionKeyService.getActiveEncryptionKeyUuid());
//    final ScrollableResults scroll = query.scroll(ScrollMode.FORWARD_ONLY);
//    final Spliterator<NamedSecret> spliterator = Spliterators.spliteratorUnknownSize(
//        new ScrollableResultIterator(scroll),
//        Spliterator.DISTINCT | Spliterator.NONNULL |
//            Spliterator.CONCURRENT | Spliterator.IMMUTABLE
//    );
//    return StreamSupport.stream(spliterator, false).onClose(scroll::close);
//  }
//
//  public List<NamedPasswordSecret> findAllPasswordsWithParametersNotEncryptedByActiveKey() {
//    return passwordRepository.findByParameterEncryptionKeyUuidNot(encryptionKeyService.getActiveEncryptionKeyUuid());
//  }
//
//  private static class ScrollableResultIterator implements Iterator<NamedSecret> {
//    private final ScrollableResults results;
//
//    ScrollableResultIterator(ScrollableResults results) {
//      this.results = results;
//    }
//
//    @Override
//    public boolean hasNext() {
//      return results.next();
//    }
//
//    @Override
//    public NamedSecret next() {
//      NamedSecret secret = new NamedSecretImpl();
//      ((ScrollableResultsImpl) results).getResultSet()
//      //      secret.setName(results.getString("name"));
//      int i = 42;
//      return (NamedSecret) results.get(0);
//    }
//  }
}
