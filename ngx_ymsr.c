/* 
 * Copyright (C) 2014 Moriyoshi Koizumi
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_flag_t enabled;
} ngx_ymsr_conf_t;

static void *ngx_ymsr_create_conf(ngx_conf_t *cf);
static char *ngx_ymsr_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_ymsr_init(ngx_conf_t *cf);
static ngx_int_t ngx_ymsr_header_filter(ngx_http_request_t *r);

static ngx_command_t  ngx_ymsr_commands[] = {

    { ngx_string("ymsr"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_ymsr_conf_t, enabled),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_ymsr_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_ymsr_init,                         /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_ymsr_create_conf,     /* create location configuration */
    ngx_ymsr_merge_conf       /* merge location configuration */
};


static char *yamashiro_words[] = {
    "保守性を考えるエンジニアが評価されないと、どんどん保守性は低くなって保守コストが高くなるってのが今まで色んな会社いた事実ですね",
    "エンジニアにメモリを与えないと転職する。あると思います。",
    "優秀なマネージメントってのは、下には「俺はコードが美しいことの価値がわかっている。ビジネス要件を満たす限り美しく作れ」といい、上には「ビジネスを満たすことが大事です。ですが、それをやるためにはプログラマが気持ちよく仕事できる最低ラインが必要です」というバランスを満たすことでは",
    "プログラマの実に83%がこのセリフを退職する人や契約を終える外注さんに言ったことがある　「この業界狭いですから」",
    "デスマの匂いしかしねぇ…",
    "エンジニアにメモリを与えないと転職する。あると思います。"
};

ngx_module_t  ngx_ymsr_module = {
    NGX_MODULE_V1,
    &ngx_ymsr_module_ctx,                  /* module context */
    ngx_ymsr_commands,                     /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;

static void *
ngx_ymsr_create_conf(ngx_conf_t *cf)
{
    ngx_ymsr_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_ymsr_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_ymsr_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_ymsr_conf_t *prev = parent;
    ngx_ymsr_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);

    return NGX_CONF_OK;
}


static ngx_int_t ngx_ymsr_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_ymsr_header_filter;

    return NGX_OK;
}

static const char *pick_yamashiro_word()
{
    const int num_words = sizeof(yamashiro_words) / sizeof(const char *);
    return yamashiro_words[ngx_random() % num_words];
}

static ngx_int_t
ngx_ymsr_header_filter(ngx_http_request_t *r)
{
    ngx_table_elt_t       *h;
    ngx_ymsr_conf_t       *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_ymsr_module);

    if (!conf->enabled) {
        return ngx_http_next_header_filter(r);
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "X-Yamashiro");
    h->value.data = pick_yamashiro_word();
    h->value.len = ngx_strlen(h->value.data);

    return ngx_http_next_header_filter(r);
}
