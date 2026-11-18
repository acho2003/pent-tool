package scanner

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/acho2003/pent-tool/internal/assessment"
)

func sourceRouteTree(t *testing.T) string {
	return nestSource(t, map[string]string{
		// NestJS service in a monorepo package.
		"apps/api/package.json": `{"dependencies":{"@nestjs/core":"10.3.0","@nestjs/common":"10.3.0"}}`,
		"apps/api/src/main.ts": `
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.setGlobalPrefix('api');
  app.enableVersioning({ type: VersioningType.URI, defaultVersion: '1' });
  await app.listen(3000);
}`,
		"apps/api/src/users/dto/list-users.dto.ts": `
export class ListUsersDto {
  @IsOptional() @IsInt() page?: number;
  @IsOptional()
  @IsString()
  search?: string;
  @IsBoolean()
  active: boolean;
}`,
		"apps/api/src/users/users.controller.ts": `
@Controller('users')
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Get()
  @UseGuards(JwtAuthGuard)
  findAll(@Query() query: ListUsersDto) {
    return this.users.list(query);
  }

  @Get(':id')
  findOne(@Param('id') id: string, @Query('expand') expand: string) {
    return this.users.find(id);
  }

  @Post()
  create(@Body() dto: CreateUserDto) {
    return this.users.create(dto);
  }

  @Version('2')
  @Delete(':id/sessions/:sessionId')
  async revoke(@Param('id') id: string, @Param('sessionId') sid: string) {}

  @Get('files/*')
  wildcard() {}
}`,
		"apps/api/src/health/health.controller.ts": `
@Controller({ path: ['health', 'status'], version: '1' })
export class HealthController {
  @Get()
  check() { return 'ok'; }
}`,
		"apps/api/src/users/users.controller.spec.ts": `@Controller('should-not-appear') export class X { @Get() a() {} }`,
		// Next.js web app in the same monorepo.
		"apps/web/package.json":                          `{"dependencies":{"next":"14.2.0","react":"18"}}`,
		"apps/web/next.config.js":                        `module.exports = { basePath: '/portal', reactStrictMode: true };`,
		"apps/web/src/app/page.tsx":                      `export default function Home() { return null }`,
		"apps/web/src/app/(marketing)/about/page.tsx":    `export default function About() { return null }`,
		"apps/web/src/app/orders/[orderId]/page.tsx":     `export default function Order() { return null }`,
		"apps/web/src/app/docs/[[...slug]]/page.tsx":     `export default function Docs() { return null }`,
		"apps/web/src/app/@modal/(.)photo/[id]/page.tsx": `export default function Modal() { return null }`,
		"apps/web/src/app/_components/page.tsx":          `export default function Private() { return null }`,
		"apps/web/src/app/api/orders/route.ts":           `export async function GET(req) {}\nexport const POST = async (req) => {}`,
		"apps/web/src/app/api/orders/[id]/route.ts":      `async function handler() {}\nexport { handler as GET, handler as DELETE }`,
		"apps/web/src/pages/legacy/index.tsx":            `export default function Legacy() { return null }`,
		"apps/web/src/pages/api/webhook.ts":              `export default function handler(req, res) {}`,
		"apps/web/src/pages/_app.tsx":                    `export default function App() { return null }`,
		"apps/web/node_modules/pkg/app/page.tsx":         `ignored`,
	})
}

func TestExtractSourceRoutesNestAndNext(t *testing.T) {
	routes, gaps := ExtractSourceRoutes(t.Context(), sourceRouteTree(t))
	var got []string
	for _, r := range routes {
		got = append(got, r.Method+" "+r.Path)
	}
	want := []string{
		// NestJS: global prefix api, URI versioning with default v1.
		"GET /api/v1/users",
		"GET /api/v1/users/{id}",
		"POST /api/v1/users",
		"DELETE /api/v2/users/{id}/sessions/{sessionId}",
		"GET /api/v1/health",
		"GET /api/v1/status",
		// Next.js with basePath /portal.
		"GET /portal",
		"GET /portal/about",
		"GET /portal/orders/{orderId}",
		"GET /portal/docs/{slug}",
		"GET /portal/docs",
		"GET /portal/api/orders",
		"POST /portal/api/orders",
		"GET /portal/api/orders/{id}",
		"DELETE /portal/api/orders/{id}",
		"GET /portal/legacy",
		"GET /portal/api/webhook",
	}
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("missing route %q", w)
		}
	}
	for _, g := range got {
		if !slices.Contains(want, g) {
			t.Errorf("unexpected route %q", g)
		}
	}
	if len(gaps) != 1 || !strings.Contains(gaps[0], "wildcard") {
		t.Fatalf("wildcard route should be reported as a gap: %v", gaps)
	}
	for _, r := range routes {
		if r.Method+" "+r.Path == "GET /api/v1/users" {
			names := map[string]string{}
			for _, q := range r.Query {
				names[q.Name] = q.Type
			}
			if names["page"] != "number" || names["search"] != "string" || names["active"] != "boolean" {
				t.Fatalf("query DTO fields not extracted: %+v", r.Query)
			}
			if r.Handler != "UsersController.findAll" || !strings.HasSuffix(r.File, "users.controller.ts") || r.Line < 2 {
				t.Fatalf("route location: %+v", r)
			}
		}
		if r.Method+" "+r.Path == "GET /api/v1/users/{id}" && (len(r.Query) != 1 || r.Query[0].Name != "expand") {
			t.Fatalf("named @Query not extracted: %+v", r.Query)
		}
	}
}

func TestExtractSourceRoutesWithoutFrameworkFindsNothing(t *testing.T) {
	root := nestSource(t, map[string]string{"package.json": `{"dependencies":{"express":"4"}}`, "src/app/page.tsx": "x", "src/c.ts": "@Controller('x') class A { @Get() a() {} }"})
	if routes, _ := ExtractSourceRoutes(t.Context(), root); len(routes) != 0 {
		t.Fatalf("routes without a Nest/Next dependency: %+v", routes)
	}
}

func TestSourceRoutesToAPIEndpointsDispatchRules(t *testing.T) {
	endpoints := SourceRoutesToAPIEndpoints([]SourceRoute{
		{Method: "GET", Path: "/api/users", Handler: "U.list", Query: []sourceRouteParam{{Name: "page", Type: "number"}, {Name: "q", Type: "string"}}},
		{Method: "GET", Path: "/api/users/{id}"},
		{Method: "POST", Path: "/api/users"},
	}, "app", "src")
	list, item, create := endpoints[0], endpoints[1], endpoints[2]
	if !list.Resolved || !list.Eligible || list.Source != sourceRoutesTool || list.DefinitionID != "source-routes:src" || list.TargetID != "app" {
		t.Fatalf("read-only route should be dispatchable: %+v", list)
	}
	if len(list.Parameters) != 2 || list.Parameters[0].Placeholder != "1" || list.Parameters[1].Placeholder != "test" || list.Parameters[0].Required {
		t.Fatalf("query placeholders: %+v", list.Parameters)
	}
	if item.Eligible || !onlyPathInputsMissing(item) || item.MissingInputs[0] != "path:id" {
		t.Fatalf("{id} route must wait for harvested values: %+v", item)
	}
	if create.Eligible || !create.Resolved {
		t.Fatalf("POST must be inventory-only: %+v", create)
	}
	url, err := apiEndpointURL("https://app.example.test/api", list)
	if err != nil || url != "https://app.example.test/api/users" {
		t.Fatalf("global prefix doubled or URL wrong: %q %v", url, err)
	}
	if raw, filled := withQueryPlaceholders(url, list); raw != "https://app.example.test/api/users?page=1&q=test" || len(filled) != 2 {
		t.Fatalf("placeholders not applied to source routes: %q %v", raw, filled)
	}
}

// End to end through the job runner: a URL target linked (related_to) to a
// local NestJS source gets the declared routes in its saved inventory, with
// source-routes provenance; {id} and POST routes stay non-dispatchable.
func TestLinkedSourceRoutesSeedTheTargetInventory(t *testing.T) {
	source := nestSource(t, map[string]string{
		"package.json": `{"dependencies":{"@nestjs/core":"10"}}`,
		"src/main.ts":  `app.setGlobalPrefix('api');`,
		"src/orders.controller.ts": `
@Controller('orders')
export class OrdersController {
  @Get('export')
  export(@Query('format') format: string) {}
  @Get(':id')
  one(@Param('id') id: string) {}
  @Post()
  create(@Body() dto: any) {}
}`,
	})
	run := func(relatedTo string) (*AttackSurface, string) {
		root := t.TempDir()
		cfg := assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Types: []assessment.Type{assessment.TypeSourceCode, assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "src", Kind: assessment.KindLocalSourcePath, Value: source}, {ID: "web", Kind: assessment.KindURL, Value: "https://app.example.test/", RelatedTo: relatedTo}}}
		plan := PlanAssessment(PlanInput{Config: cfg})
		jobs := plan.Jobs[:0]
		for _, job := range plan.Jobs {
			if job.Scanner == "katana" && job.TargetID == "web" {
				job.Dependencies = nil
				jobs = append(jobs, job)
			}
		}
		if len(jobs) != 1 {
			t.Fatalf("expected the crawl job that prepares the inventory: %+v", plan.Jobs)
		}
		plan.Jobs = jobs
		NewPipeline(Config{KatanaPath: "/nonexistent/katana"}).RunAssessmentJobs(t.Context(), plan, root, nil, nil)
		for _, surface := range LoadAttackSurfaces(root) {
			if strings.Contains(surface.Scope, "web") {
				s := surface
				return &s, root
			}
		}
		t.Fatal("no inventory saved for the URL target")
		return nil, root
	}
	surface, root := run("src")
	byURL := map[string]AttackSurfaceEndpoint{}
	for _, ep := range surface.Endpoints {
		byURL[ep.Method+" "+ep.URL] = ep
	}
	exportRoute, ok := byURL["GET https://app.example.test/api/orders/export?format=test"]
	if !ok || exportRoute.State != EndpointStateInScope || !slices.ContainsFunc(exportRoute.Provenance, func(p EndpointProvenance) bool { return p.Tool == sourceRoutesTool }) {
		t.Fatalf("read-only source route not seeded as dispatchable: %+v (all: %v)", exportRoute, keys(byURL))
	}
	for key, ep := range byURL {
		if strings.Contains(key, "{id}") && ep.State != EndpointStateUnmaterialized {
			t.Fatalf("{id} route dispatchable without a value: %+v", ep)
		}
		if strings.HasPrefix(key, "POST ") && ep.State == EndpointStateInScope {
			if eligible, _ := endpointEligibleWithPolicy(ep, "zap", nil, true); eligible {
				t.Fatalf("POST source route is dispatchable: %+v", ep)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(root, "discovery", stableJobPath("web"), "source-routes.json")); err != nil {
		t.Fatalf("route evidence not saved: %v", err)
	}
	unlinked, _ := run("")
	for _, ep := range unlinked.Endpoints {
		if slices.ContainsFunc(ep.Provenance, func(p EndpointProvenance) bool { return p.Tool == sourceRoutesTool }) {
			t.Fatalf("source routes seeded without an explicit related_to link: %+v", ep)
		}
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
