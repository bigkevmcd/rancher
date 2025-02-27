package tokens

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/rancher/norman/api/writer"
	"github.com/rancher/norman/types"
	v32 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/tokens/hashers"
	"github.com/rancher/rancher/pkg/features"
	v3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	mgmtFakes "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3/fakes"
	"github.com/rancher/wrangler/v3/pkg/randomtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/pointer"
)

type DummyIndexer struct {
	cache.Store

	hashedEnabled bool
}

type TestCase struct {
	token   string
	userID  string
	receive bool
	err     string
}

var (
	token       string
	tokenHashed string
)

type TestManager struct {
	assert       *assert.Assertions
	tokenManager Manager
	apiCtx       *types.APIContext
	testCases    []TestCase
}

// TestTokenStreamTransformer validates that the function properly filters data in websocket
func TestTokenStreamTransformer(t *testing.T) {
	features.TokenHashing.Set(false)

	testManager := TestManager{
		assert: assert.New(t),
		tokenManager: Manager{
			tokenIndexer: &DummyIndexer{
				Store: &cache.FakeCustomStore{},
			},
		},
		apiCtx: &types.APIContext{
			Request: &http.Request{},
		},
	}

	var err error
	token, err = randomtoken.Generate()
	if err != nil {
		testManager.assert.FailNow(fmt.Sprintf("unable to generate token for token stream transformer test: %v", err))
	}
	sha256Hasher := hashers.Sha256Hasher{}
	tokenHashed, err = sha256Hasher.CreateHash(token)
	if err != nil {
		testManager.assert.FailNow(fmt.Sprintf("unable to hash token for token stream transformer test: %v", err))
	}

	testManager.testCases = []TestCase{
		{
			token:   "testname:" + token,
			userID:  "testuser",
			receive: true,
			err:     "",
		},
		{
			token:   "testname:testtoken",
			userID:  "testuser",
			receive: false,
			err:     "Invalid auth token value",
		},
		{
			token:   "wrongname:testkey",
			userID:  "testuser",
			receive: false,
			err:     "422: [TokenStreamTransformer] failed: Invalid auth token value",
		},
		{
			token:   "testname:wrongkey",
			userID:  "testname",
			receive: false,
			err:     "422: [TokenStreamTransformer] failed: Invalid auth token value",
		},
		{
			token:   "testname:" + token,
			userID:  "diffname",
			receive: false,
			err:     "",
		},
		{
			token:   "",
			userID:  "testuser",
			receive: false,
			err:     "401: [TokenStreamTransformer] failed: No valid token cookie or auth header",
		},
	}

	testManager.runTestCases(false)
	testManager.runTestCases(true)
}

func (t *TestManager) runTestCases(hashingEnabled bool) {
	features.TokenHashing.Set(hashingEnabled)
	t.tokenManager = Manager{
		tokenIndexer: &DummyIndexer{
			Store:         &cache.FakeCustomStore{},
			hashedEnabled: hashingEnabled,
		},
	}
	for index, testCase := range t.testCases {
		failureMessage := fmt.Sprintf("test case #%d failed", index)

		dataStream := make(chan map[string]interface{}, 1)
		dataReceived := make(chan bool, 1)

		t.apiCtx.Request.Header = map[string][]string{"Authorization": {fmt.Sprintf("Bearer %s", testCase.token)}}

		df, err := t.tokenManager.TokenStreamTransformer(t.apiCtx, nil, dataStream, nil)
		if testCase.err == "" {
			t.assert.Nil(err, failureMessage)
		} else {
			t.assert.NotNil(err, failureMessage)
			t.assert.Contains(err.Error(), testCase.err, failureMessage)
		}

		ticker := time.NewTicker(1 * time.Second)
		go receivedData(df, ticker.C, dataReceived)

		// test data is received when data stream contains matching userID
		dataStream <- map[string]interface{}{"labels": map[string]interface{}{UserIDLabel: testCase.userID}}
		t.assert.Equal(<-dataReceived, testCase.receive)
		close(dataStream)
		ticker.Stop()
	}
}

// TODO: Test for GetSecret

func receivedData(c <-chan map[string]interface{}, t <-chan time.Time, result chan<- bool) {
	select {
	case <-c:
		result <- true
	case <-t:
		// assume data will not be received after 1 second timeout
		result <- false
	}
}

func (d *DummyIndexer) Index(indexName string, obj interface{}) ([]interface{}, error) {
	return nil, nil
}

func (d *DummyIndexer) IndexKeys(indexName, indexKey string) ([]string, error) {
	return []string{}, nil
}

func (d *DummyIndexer) ListIndexFuncValues(indexName string) []string {
	return []string{}
}

func (d *DummyIndexer) ByIndex(indexName, indexKey string) ([]interface{}, error) {
	token := &v3.Token{
		Token: token,
		ObjectMeta: v1.ObjectMeta{
			Name: "testname",
		},
		UserID: "testuser",
	}
	if d.hashedEnabled {
		token.Annotations = map[string]string{TokenHashed: strconv.FormatBool(d.hashedEnabled)}
		token.Token = tokenHashed
	}
	return []interface{}{
		token,
	}, nil
}

func (d *DummyIndexer) GetIndexers() cache.Indexers {
	return nil
}

func (d *DummyIndexer) AddIndexers(newIndexers cache.Indexers) error {
	return nil
}

func (d *DummyIndexer) SetTokenHashed(enabled bool) {
	d.hashedEnabled = enabled
}

func TestUserAttributeCreateOrUpdateSetsLastLoginTime(t *testing.T) {
	createdUserAttribute := &v3.UserAttribute{}

	userID := "u-abcdef"
	manager := Manager{
		userLister: &mgmtFakes.UserListerMock{
			GetFunc: func(namespace, name string) (*v3.User, error) {
				return &v3.User{
					ObjectMeta: v1.ObjectMeta{
						Name: userID,
					},
					Enabled: pointer.BoolPtr(true),
				}, nil
			},
		},
		userAttributeLister: &mgmtFakes.UserAttributeListerMock{
			GetFunc: func(namespace, name string) (*v3.UserAttribute, error) {
				return &v3.UserAttribute{}, nil
			},
		},
		userAttributes: &mgmtFakes.UserAttributeInterfaceMock{
			UpdateFunc: func(userAttribute *v3.UserAttribute) (*v3.UserAttribute, error) {
				return userAttribute.DeepCopy(), nil
			},
			CreateFunc: func(userAttribute *v3.UserAttribute) (*v3.UserAttribute, error) {
				createdUserAttribute = userAttribute.DeepCopy()
				return createdUserAttribute, nil
			},
		},
	}

	groupPrincipals := []v3.Principal{}
	userExtraInfo := map[string][]string{}

	loginTime := time.Now()
	err := manager.UserAttributeCreateOrUpdate(userID, "provider", groupPrincipals, userExtraInfo, loginTime)
	assert.NoError(t, err)

	// Make sure login time is set and truncated to seconds.
	assert.Equal(t, loginTime.Truncate(time.Second), createdUserAttribute.LastLogin.Time)
}

func TestUserAttributeCreateOrUpdateUpdatesGroups(t *testing.T) {
	updatedUserAttribute := &v3.UserAttribute{}

	userID := "u-abcdef"
	manager := Manager{
		userLister: &mgmtFakes.UserListerMock{
			GetFunc: func(namespace, name string) (*v3.User, error) {
				return &v3.User{
					ObjectMeta: v1.ObjectMeta{
						Name: userID,
					},
					Enabled: pointer.BoolPtr(true),
				}, nil
			},
		},
		userAttributeLister: &mgmtFakes.UserAttributeListerMock{
			GetFunc: func(namespace, name string) (*v3.UserAttribute, error) {
				return &v3.UserAttribute{
					ObjectMeta: v1.ObjectMeta{
						Name: userID,
					},
				}, nil
			},
		},
		userAttributes: &mgmtFakes.UserAttributeInterfaceMock{
			UpdateFunc: func(userAttribute *v3.UserAttribute) (*v3.UserAttribute, error) {
				updatedUserAttribute = userAttribute.DeepCopy()
				return updatedUserAttribute, nil
			},
			CreateFunc: func(userAttribute *v3.UserAttribute) (*v3.UserAttribute, error) {
				return userAttribute.DeepCopy(), nil
			},
		},
	}

	groupPrincipals := []v3.Principal{
		{
			ObjectMeta: v1.ObjectMeta{
				Name: "group1",
			},
		},
	}
	userExtraInfo := map[string][]string{}

	err := manager.UserAttributeCreateOrUpdate(userID, "provider", groupPrincipals, userExtraInfo)
	assert.NoError(t, err)

	require.Len(t, updatedUserAttribute.GroupPrincipals, 1)
	principals := updatedUserAttribute.GroupPrincipals["provider"]
	require.NotEmpty(t, principals)
	require.Len(t, principals.Items, 1)
	assert.Equal(t, principals.Items[0].Name, "group1")
}

func TestCreateTokenAndSetCookieWithAuthToken(t *testing.T) {
	fc := &fakeTokensClient{}
	secrets := &fakeSecretsInterface{}
	m := Manager{
		tokensClient: fc,
		secretLister: &fakeSecretLister{
			map[string]*corev1.Secret{
				"testuser-secret": &corev1.Secret{
					Data: map[string][]byte{},
				},
			},
		},
		secrets: secrets,
	}
	userPrincipal := v3.Principal{
		Provider: "github",
	}
	username := "testuser"
	req := httptest.NewRequest(http.MethodPost, "https://rancher.example.com/test", nil)
	resp := httptest.NewRecorder()
	err := m.CreateTokenAndSetCookieWithAuthToken(username, userPrincipal,
		[]v3.Principal{},
		"this-is-a-secret-token", 1000, "test description",
		&types.APIContext{
			Schemas:  types.NewSchemas(),
			Request:  req,
			Response: resp,
			ResponseWriter: &writer.EncodingResponseWriter{
				ContentType: "application/json",
				Encoder:     types.JSONEncoder,
			},
		})
	assert.NoError(t, err)

	want := []*v32.Token{
		{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Token",
				APIVersion: "management.cattle.io/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "token-mmls2",
				Labels: map[string]string{
					"authn.management.cattle.io/token-userId": username,
				},
			},
			Token: "test-random-token",
		},
	}
	assert.Equal(t, want, fc.created)

	cookie, err := http.ParseSetCookie(resp.Header().Get("Set-Cookie"))
	assert.NoError(t, err)
	assert.Regexp(t, "^token-mmls2:", cookie.Value)

	wantSecrets := []*corev1.Secret{
		{
			Data: map[string][]byte{
				"github": []byte("this-is-a-secret-token"),
			},
		},
	}
	assert.Equal(t, secrets.updated, wantSecrets)
}

type fakeTokensClient struct {
	created []*v32.Token
}

func (c *fakeTokensClient) Create(k8sToken *v32.Token) (*v32.Token, error) {
	tok := &v32.Token{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "management.cattle.io/v3",
			Kind:       "Token",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				UserIDLabel: k8sToken.UserID,
			},
			Name: "token-mmls2",
		},
		Token: "test-random-token",
	}
	c.created = append(c.created, tok)

	return tok, nil
}

func (c *fakeTokensClient) Get(name string, opts metav1.GetOptions) (*v32.Token, error) {
	return nil, nil
}

func (c *fakeTokensClient) Update(*v32.Token) (*v32.Token, error) {
	return nil, nil
}

func (c *fakeTokensClient) Delete(name string, options *metav1.DeleteOptions) error {
	return nil
}

func (c *fakeTokensClient) List(opts metav1.ListOptions) (*v32.TokenList, error) {
	return nil, nil
}

type fakeSecretLister struct {
	secrets map[string]*corev1.Secret
}

func (f *fakeSecretLister) List(namespace string, selector labels.Selector) ([]*corev1.Secret, error) {
	return nil, nil
}

func (f *fakeSecretLister) Get(namespace, name string) (*corev1.Secret, error) {
	secret := f.secrets[name]
	if secret == nil {
		return nil, errors.NewNotFound(schema.GroupResource{Resource: "secrets"}, name)
	}

	return secret, nil
}

type fakeSecretsInterface struct {
	created []*corev1.Secret
	updated []*corev1.Secret
}

func (f *fakeSecretsInterface) Create(s *corev1.Secret) (*corev1.Secret, error) {
	f.created = append(f.created, s)
	return s, nil
}

func (f *fakeSecretsInterface) Update(s *corev1.Secret) (*corev1.Secret, error) {
	f.updated = append(f.updated, s)
	return s, nil
}
